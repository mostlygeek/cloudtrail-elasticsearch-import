#!/usr/bin/env node

/* 
 * Steps: 
 * 
 * 1. do an S3 list of stuff under a specific prefix 
 * 2. for each file, download it, unzip it and extract the json
 * 3. extract the events and put them into ElasticSearch
 * 4. record in elastic-search that the file was processed
 * 5. repeat
 */

const 
    ES_FILE_CONCURRENCY=1    /* how many concurrent S3 cloudtrail files to do */
    , ES_EVENT_CONCURRENCY=5   /* how many concurrent event index requests to make */
    ; 

var AWS = require('aws-sdk')
    , program = require('commander')
    , async = require('async')
    , zlib = require('zlib')
    , url = require('url')
    , elastical = require('elastical')
    , debug = require('debug')
    , d = { 
        ESError : debug("ElasticSearch:error")
        , info : debug("info")
    } ;

program
    .version('0.0.1')
    .option('-b, --bucket <sourcebucket>', 'Bucket with cloudtrail logs', String, '')
    .option('-r, --region <bucket region>', 'Default region: us-west-2', String, 'us-west-2')
    .option('-p, --prefix <prefix>', 'prefix where to start listing objects')

    .option('-e, --elasticsearch <url>', 'ES base, ie: https://host:port', String, '')
    .option('--work-index <name>', 'ES index to record imported files, def: cloudtrail-imported', String, 'cloudtrail-import-log')
    .option('--cloudtrail-index <name>', 'ES index to put cloudtrail events, def: cloudtrail', String, 'cloudtrail')
    .parse(process.argv);

/*
 * TODO put some error / param checking code here
 */

if (program.elasticsearch) {
    var urlParts = url.parse(program.elasticsearch);
    var ES = new elastical.Client(urlParts.hostname, {port: (urlParts.port ? urlParts.port : 9200)});
} else {
    console.error("--elasticsearch required");
    process.exit(1);
}

/*
 * yah these need to exists 
 */
AWS.config.update({
    accessKeyId : process.env.AWS_ACCESS_KEY,
    secretAccessKey : process.env.AWS_SECRET_KEY
});

var sourceS3 = new AWS.S3({region: program.region})
    processQueue = async.queue(processItemWorker, ES_FILE_CONCURRENCY); 

sourceS3.listObjects({Bucket: program.bucket, Prefix: program.prefix}, function(err, data) {
    //console.log(err, data.Contents.length);
    processQueue.push(data.Contents);
});

function processItemWorker(task, processItemWorkerCB) {
    var jsonSrc = '', 
        _id = task.ETag.replace(/"/g, '');

    // check elastic cache to see if the Key has already been processed
    //
    ES.get(program.workIndex, _id, function(err, doc, res) {
        if (res && res.error && res.error.indexOf('IndexMissingException') != 0) {
            d.ESError(res.error);
            workerCB();
            return;
        }

        if (res && res.exists == true) {
            d.info("skip %s, already exists", _id);
            processItemWorkerCB();
            return;
        }


        d.info("Processing: %s", task.Key);
        var doc = {
            _id : _id
            , key : task.Key
            , processed: (new Date).toString
        };

        /* 
         * this downloads, streams it into zlib to be decompressed
         */
        var stream = sourceS3.getObject({
                Bucket: program.bucket
                , Key: task.Key}
            ).createReadStream().pipe(zlib.createGunzip());

        stream.on('data', function(data) { jsonSrc += data.toString(); });

        stream.on('end', function() {
            var o = JSON.parse(jsonSrc); 

            var indexQueue = async.queue(function(task, workerCB) {
                ES.index(program.cloudtrailIndex, "event", task, function(err, res) {
                    d.info("Indexed: %s on %s by %s", task.eventName, task.eventSource, task.userIdentity.arn);
                    workerCB();
                });
            }, ES_EVENT_CONCURRENCY);

            d.info("Indexing %d items", o.Records.length);
            indexQueue.push(o.Records);
            indexQueue.drain = function() {

                // mark that we've already processed this
                ES.index(program.workIndex, "s3obj", doc, {id: _id}, function(err, res) {
                    processItemWorkerCB();
                });
            }
        });
    });
    
}

