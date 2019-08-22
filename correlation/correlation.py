# Copyright (c) Authors of Clover
#
# All rights reserved. This program and the accompanying materials
# are made available under the terms of the Apache License, Version 2.0
# which accompanies this distribution, and is available at
# http://www.apache.org/licenses/LICENSE-2.0

import logging
import redis
import requests
import threading
import time

from jaeger_client import Config
from pymongo import MongoClient

TRACING_IP = "jaeger-query.clovisor"
TRACING_PORT = "80"
REDIS_IP = "redis.clovisor"
MONGO_URL = "mongo.clovisor:27017"
COMMAND_CHANNEL = "clovisor_correlation_cfg"


class Tracing:

    def __init__(self, tracing_ip=TRACING_IP, tracing_port=TRACING_PORT,
                 redis_ip=REDIS_IP):
        self.tracing_ip = tracing_ip
        self.tracing_port = tracing_port
        try:
            self.r = redis.StrictRedis(host=redis_ip, port=6379, db=0)
        except Exception:
            print("Failed to connect to redis")

        try:
            self.m = MongoClient(MONGO_URL)
        except Exception:
            print("Failed to connect to MongoDB")

        self._db = self.m.clovisor
        self._trace_table = self._db['traces']


    def getServices(self):
        req_url = 'http://' + self.tracing_ip + ':' + self.tracing_port + \
                                                        '/api/services'
        try:
            response = requests.get(req_url)
            if response.status_code != 200:
                print("ERROR: Cannot connect to tracing: {}".format(
                                        response.status_code))
                return False
        except Exception as e:
            print("ERROR: Cannot connect to tracing")
            print(e)
            return False

        data = response.json()
        services = data['data']
        return services

    def getTraces(self, service, time_back=3600, limit='1000'):
        ref_time = int(time.time())
        pad_time = '757000'
        end_time = 'end=' + str(ref_time) + pad_time + '&'
        if time_back == 0:
            delta = self.test_start_time
        else:
            delta = ref_time - time_back
        start_time = 'start=' + str(delta) + pad_time
        limit = 'limit=' + limit + '&'
        loopback = 'loopback=1h&'
        max_dur = 'maxDuration&'
        min_dur = 'minDuration&'
        service = 'service=' + service + '&'
        url_prefix = 'http://' + self.tracing_ip + ':' + self.tracing_port + \
            '/api/traces?'
        req_url = url_prefix + end_time + limit + loopback + max_dur + \
            min_dur + service + start_time

        try:
            response = requests.get(req_url)
            if response.status_code != 200:
                print("ERROR: Cannot connect to tracing: {}".format(
                                        response.status_code))
                return False
        except Exception as e:
            print("ERROR: Cannot connect to tracing")
            print(e)
            return False

        traces = response.json()
        return traces

    def numTraces(self, trace):
        num_traces = len(trace['data'])
        return (num_traces)

    def outTraces(self, service, trace):
        for traces in trace['data']:
            print("TraceID: {}".format(traces['traceID']))
            for spans in traces['spans']:
                #print(spans)
                self.insertDB(service, spans)

    def insertDB(self, service, spans):
        insert_val = {}
        insert_val['service'] = service
        tags = spans['tags']
        for tag in tags:
            if tag['key'].startswith('sampler'):
                continue
            key = tag['key']
            val = tag['value']
            insert_val[key] = val

        print("insert_val is {}".format(insert_val))
        if len(insert_val) > 1:
            self._trace_table.replace_one(
                {'traceid': insert_val['traceid'],
                 'srcip': insert_val['srcip'],
                 'dstip': insert_val['dstip'],
                 'srcport': insert_val['srcport'],
                 'dstport': insert_val['dstport']},
                insert_val,
                upsert=True
            )

            # debug
            """
            print("Check on MongoDB....")
            cursor = self._trace_table.find({})
            for document in cursor:
                print(document)
            """

    def processCommand(self, command):
        cmd = str(command)
        print("command {}".format(cmd))
        if cmd.startswith("correlate"):
            traceid = cmd.split(':')[1]
            print("trace id is {}".format(traceid))
            traces = list(self._trace_table.find({'traceid': traceid}))
            for trace in traces:
                print("service: {}".format(trace['service']))
                print("node: {}".format(trace['nodename']))
                print("pod: {}".format(trace['podname']))
                print("duration: {}".format(trace['duration']))


    def monitorTraces(self, sample_interval=1):
        loop = True
        while loop:
            try:
                s = self.getServices()
                for service in s:
                    if service.startswith("jaeger-query"):
                        continue
                    t = self.getTraces(service, 10)
                    num_traces = self.numTraces(t)
                    if num_traces > 0:
                        print("Number of traces for service: " + service + " " + str(num_traces))
                        self.outTraces(service, t)

                time.sleep(sample_interval)
            except KeyboardInterrupt:
                print("Test Start: {}".format(self.test_start_time))
                loop = False

    def commandCB(self):
        print("commandCB invoked....")
        pubsub = self.r.pubsub()
        pubsub.subscribe(COMMAND_CHANNEL)
        while True:
            for message in pubsub.listen():
                print("Got Message!!!!")
                command = message['data']
                self.processCommand(command)

    def main(self):
        print("Start thread...")
        t = threading.Thread(target=self.commandCB)
        t2 = threading.Thread(target=self.monitorTraces)
        #t.setDaemon(True)
        #t2.setDaemon(True)
        t.start()
        t2.start()
        t.join()
        t2.join()
        #self.monitorTraces(1)


if __name__ == '__main__':
    Tracing(TRACING_IP, TRACING_PORT).main()
