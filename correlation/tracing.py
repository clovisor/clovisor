# Copyright (c) Authors of Clover
#
# All rights reserved. This program and the accompanying materials
# are made available under the terms of the Apache License, Version 2.0
# which accompanies this distribution, and is available at
# http://www.apache.org/licenses/LICENSE-2.0

import requests
import time
import redis

TRACING_IP = "jaeger-query.clovisor"
TRACING_PORT = "30693"
REDIS_IP = "redis.clovisor"


class Tracing:

    def __init__(self, tracing_ip=TRACING_IP, tracing_port=TRACING_PORT,
                 redis_ip=REDIS_IP):
        self.tracing_ip = tracing_ip
        self.tracing_port = tracing_port
        try:
            self.r = redis.StrictRedis(host=redis_ip, port=6379, db=0)
        except Exception:
            print("Failed to connect to redis")


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
        return str(num_traces)

    def outTraces(self, trace):
        for traces in trace['data']:
            print("TraceID: {}".format(traces['traceID']))
            for spans in traces['spans']:
                print(spans)

    def monitorTraces(self, sample_interval):
        loop = True
        while loop:
            try:
                s = self.getServices()
                for service in s:
                    t = self.getTraces(service, 10)
                    num_traces = self.numTraces(t)
                    print("Number of traces: " + num_traces)
                self.outTraces(t)
                time.sleep(sample_interval)
            except KeyboardInterrupt:
                print("Test Start: {}".format(self.test_start_time))
                loop = False

    def main(self):
        self.monitorTraces(1)


if __name__ == '__main__':
    Tracing(TRACING_IP, TRACING_PORT).main()
