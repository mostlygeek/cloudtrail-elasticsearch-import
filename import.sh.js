#!/usr/bin/env node

/* 
 * Steps: 
 * 
 * - make sure indexes exist, create them if they don't
 * - do an S3 list of stuff under a specific prefix 
 * - for each file, download it, unzip it and extract the json
 * - extract the events and put them into ElasticSearch
 * - record in elastic-search that the file was processed
 * - repeat
 */

const 
    ES_FILE_CONCURRENCY=1    /* how many concurrent S3 cloudtrail files to do */
    ; 

var AWS = require('aws-sdk')
    , program = require('commander')
    , async = require('async')
    , zlib = require('zlib')
    , url = require('url')
    , elastical = require('elastical')
    , moment = require('moment')
    , debug = require('debug')
    , d = { 
        ESError : debug("ElasticSearch:error")
        , info : debug("info")
        , error: debug("error")
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

async.auto({
    ensureIndexes: function(cb) {
        ensureIndexes(ES, program.workIndex, program.cloudtrailIndex, function(err) {
            if (err) {
                d.error("ERROR creating indexes: %s", err);
                cb(err);
            } else {
                d.info("Done creating indexes");
                cb(null);
            }
        });
    }
    , listS3Objs: ["ensureIndexes", function(listS3ObjsCB, results) {
        var sourceS3 = new AWS.S3({region: program.region});
        var d = debug("listS3Objs");

        /*
         * this is sort of like a cheap tail recursion of 
         * listing the S3 objects we need 
         */
        (function _fetch(bucket, prefix, marker, list) {
            list = list || [];

            var params = { Bucket: bucket , Prefix : prefix };
            if (!!marker === true) { params.Marker = marker; }


            /* fetch a list of all the objects to be processed based on the prefix*/

            d("Fetching %s with marker: %s", prefix, marker);
            sourceS3.listObjects(params, function(err, data) {
                if (err) {
                    d("ERROR: %s", err);
                    listS3ObjsCB(err);
                    return;
                }

                if (data.Contents.length > 0) {
                    list = list.concat(data.Contents);
                    if (data.IsTruncated == true) {
                        var marker = data.Contents[data.Contents.length-1].Key;
                        _fetch(bucket, prefix, marker, list);
                    } else {
                        listS3ObjsCB(null, list);
                    }
                } else {
                    listS3ObjsCB(null, list);
                }
            });
        })(program.bucket, program.prefix); // kick it off...
    }]
}, function(err, results) {
    if (err) {
        d.error("ERROR: %s", err); 
        return;
    }

    d.info("Processing %d S3 Objects", results.listS3Objs.length);

    var processQueue = async.queue(processItemWorker, ES_FILE_CONCURRENCY); 

    var S3 = new AWS.S3({region: program.region});

    if (results.listS3Objs.length > 0) {
        for (var i=0, l=results.listS3Objs.length; i<l; i++) {
            processQueue.push({
                Bucket                : program.bucket
                , S3                  : S3
                , Key                 : results.listS3Objs[i].Key
                , ETag                : results.listS3Objs[i].ETag
                , workIndexName       : program.workIndex
                , cloudtrailIndexName : program.cloudtrailIndex
            });
        }
    }
});

/*
    //console.log(err, data.Contents.length);
    processQueue.push(data.Contents);
});
*/


/**
 * Ensures the necessary ElasticSearch Indexes Exist
 *
 * @method ensureIndexes
 * @param {Elastical.client} initialized Elastical.Client
 * @param {String} name of index for keeping track of processed objects
 * @param {String} name of index for cloudtrail events
 * @param {Function} [callback] Callback function
 *      @param {Error|null} 
 */
function ensureIndexes(ES, workIndexName, cloudtrailIndexName, topCB) {
    var d = debug("ensureIndexes");

    async.auto({
        workIndex: function(cb) { ES.indexExists(workIndexName, cb); }
        , CTIndex: function(cb) { ES.indexExists(cloudtrailIndexName, cb); }
        , makeWorkIndex: ["workIndex", function(cb, results) {
            if (results.workIndex === true) {
                d("Exists: %s", workIndexName);
                setImmediate(cb.bind(this, null, true));
                return;
            }

            d("Creating %s", workIndexName);
            var options = {
                mappings: {
                    s3obj: {
                        properties: {
                            timestamp: { type: "date"}//, format: "basic_date_time_no_millis"} 
                        }
                    }
                }
            };

            ES.createIndex(workIndexName, options, function(err, index, res) {
                cb(err, res);
            });
        }]
        , makeCTIndex: ["CTIndex", function(cb, results) {
            if (results.CTIndex === true) {
                d("Exists: %s", cloudtrailIndexName);
                setImmediate(cb.bind(this, null, true));
                return;
            }

            d("Creating %s", cloudtrailIndexName);
            var options = {
                mappings: {
                    event: { 
                        properties: {
                            eventTime: { type: "date", format: "date_time_no_millis"} 
                        }
                   }
                }
            };

            ES.createIndex(cloudtrailIndexName, options, cb);
        }]
    }, function(err, results) {
        if (err) { 
            d("ERROR: %s", err);
            return topCB(err); 
        }
        topCB(null);
    });
}

function processItemWorker(task, processItemWorkerCB) {
    var jsonSrc = '', 
        ETag = task.ETag.replace(/"/g, '');

    // check elastic cache to see if the Key has already been processed
    ES.get(task.workIndexName, ETag, function(err, doc, res) {
        if (res && res.error) {
            d.ESError(res.error);
            processItemWorkerCB();
            return;
        }

        if (res && res.exists == true) {
            d.info("skip %s, already exists", ETag);
            processItemWorkerCB();
            return;
        }

        d.info("Processing: %s", task.Key);

        /* 
         * this downloads, streams it into zlib to be decompressed
         */
        var stream = task.S3.getObject({
                Bucket: task.Bucket
                , Key: task.Key}
            ).createReadStream().pipe(zlib.createGunzip());

        stream.on('data', function(data) { jsonSrc += data.toString(); });

        stream.on('end', function() {
            var o = JSON.parse(jsonSrc); 

            // ref: https://github.com/ramv/node-elastical/blob/master/lib/client.js#L129
            var _bulk = [];
            for (var i=0,l=o.Records.length; i<l; i++) {
                _bulk.push({
                    index: {
                        index: task.cloudtrailIndexName
                        , type: "event"
                        , data: o.Records[i]
                    }
                });
            }

            var doc = {
                _id : ETag
                , key : task.Key
                , timestamp: moment().format()
            };

            // will mark the s3 object as done
            _bulk.push({
                index: {
                    index: task.workIndexName
                    , type: "s3obj"
                    , data: doc
                    , id: ETag
                }
            });

            ES.bulk(_bulk, function(err, res) {
                if (err) {
                    d.info("Error bulk index: %s", err);
                } else {
                    d.info("Bulk indexed %d items", _bulk.length);
                }

                processItemWorkerCB();
            });
        });
    });
    
}

