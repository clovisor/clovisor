// Copyright (c) Authors of Clover
//
// All rights reserved. This program and the accompanying materials
// are made available under the terms of the Apache License, Version 2.0
// which accompanies this distribution, and is available at
// http://www.apache.org/licenses/LICENSE-2.0

package clovisor

import (
    "bytes"
    "encoding/binary"
    "fmt"
    "io"
    "net"
    "os"
    "strconv"
    "strings"
    "gopkg.in/yaml.v2"

    "github.com/go-redis/redis"
    opentracing "github.com/opentracing/opentracing-go"
    jaeger "github.com/uber/jaeger-client-go"
    jaeger_config "github.com/uber/jaeger-client-go/config"
)

var redisServer string = "redis.clovisor"
var jaegerCollector string = "jaeger-collector.clovisor:14268"
var jaegerAgent string = "jaeger-agent.clovisor:6831"
var ProtoCfg string = "clovisor_proto_cfg"
var clovisorCfgChan string = "clovisor_cfg_chan"

/*
 * redisConnect: redis client connecting to redis server
 */
func redisConnect() *redis.Client {
    client := redis.NewClient(&redis.Options{
        Addr:       fmt.Sprintf("%s:6379", redisServer),
        Password:   "",
        DB:         0,
    })
    return client
}

func get_cfg_labels(node_name string) ([]string, error) {
    client := redisConnect()
    defer client.Close()
    labels_list, err := client.LRange("clovisor_labels", 0, -1).Result()
    if err != nil {
        fmt.Println(err.Error())
        return nil, err
    }

    return labels_list, err
}

func parse_label_cfg(label_cfg string) (string, string, string) {
    label_slice := strings.Split(label_cfg, ":")
    if len(label_slice) == 1 {
        return label_slice[0], "", ""
    }
    return label_slice[0], label_slice[1], label_slice[2]
}

func get_egress_match_list(pod_name string) ([]egress_match_t) {
    client := redisConnect()
    defer client.Close()
    egress_cfg_list, err := client.LRange("clovior_egress_match", 0, -1).Result()
    if err != nil {
        fmt.Println(err.Error())
        return nil
    }
    ret_list := make([]egress_match_t, 0, len(egress_cfg_list))
    for _, em_cfg_str := range(egress_cfg_list) {
        fmt.Printf("egress match cfg == %v\n", em_cfg_str)
        em_cfg_slice := strings.Split(em_cfg_str, ":")
        if len(em_cfg_slice) < 2 {
            fmt.Printf("egress match config requires at least two fields [%v]\n", em_cfg_slice)
            continue
        } else if len(em_cfg_slice) == 3 {
            if strings.Contains(pod_name, em_cfg_slice[2]) {
                fmt.Printf("%v != %v, filtering out this config for pod %v\n",
                           em_cfg_slice[2], pod_name, pod_name)
                continue
            }
        }
        var ip uint32 = 0
        if em_cfg_slice[0] != "0" {
            ip = ip2Long(em_cfg_slice[0])
        }
        port_32, _ := strconv.Atoi(em_cfg_slice[1])
        port := uint16(port_32)
        ret_list = append(ret_list,  egress_match_t{ip, port})
    }
    return ret_list
}

// following function comes from
// https://www.socketloop.com/tutorials/golang-convert-ip-address-string-to-long-unsigned-32-bit-integer
func ip2Long(ip string) uint32 {
    var long uint32
    //binary.Read(bytes.NewBuffer(net.ParseIP(ip).To4()), binary.LittleEndian, &long)
    binary.Read(bytes.NewBuffer(net.ParseIP(ip).To4()), binary.BigEndian, &long)
    return long
}

func backtoIP4(ipInt int64) string {
    // need to do two bit shifting and “0xff” masking
    b0 := strconv.FormatInt((ipInt>>24)&0xff, 10)
    b1 := strconv.FormatInt((ipInt>>16)&0xff, 10)
    b2 := strconv.FormatInt((ipInt>>8)&0xff, 10)
    b3 := strconv.FormatInt((ipInt & 0xff), 10)
    return b0 + "." + b1 + "." + b2 + "." + b3
}

func get_cfg_session_match() ([]egress_match_cfg, error) {
    var ret_list []egress_match_cfg
    client := redisConnect()
    defer client.Close()
    keys, err := client.HKeys("clovisor_session_match").Result()
    if err != nil {
        fmt.Println(err.Error())
        return nil, err
    }
    for _, key := range keys {
        value, err := client.HGet("clovisor_session_match", key).Result()
        if err != nil {
            fmt.Println(err.Error())
            continue
        }
        match_slice := strings.Split(key, "-")
        dst_ip := ip2Long(match_slice[0])
        dst_port, _ := strconv.Atoi(match_slice[1])
        egress_match := egress_match_t{
                dst_ip:     dst_ip,
                dst_port:   uint16(dst_port),
        }
        // organize into internally understandable struct
        ret_list = append(ret_list, egress_match_cfg{
                                        egress_match:   egress_match,
                                        action:         value,
                                    })
    }
    return ret_list, nil
}

func initJaeger(service string) (opentracing.Tracer, io.Closer) {
    cfg := &jaeger_config.Configuration{
        Sampler: &jaeger_config.SamplerConfig{
            Type:  "const",
            Param: 1,
        },
        Reporter: &jaeger_config.ReporterConfig{
            LogSpans: true,
            CollectorEndpoint: fmt.Sprintf("http://%s/api/traces", jaegerCollector),
            LocalAgentHostPort: fmt.Sprintf("%s", jaegerAgent),
        },
    }
    tracer, closer, err := cfg.New(service, jaeger_config.Logger(jaeger.StdLogger))
    if err != nil {
        panic(fmt.Sprintf("ERROR: cannot init Jaeger: %v\n", err))
    }
    return tracer, closer
}

func get_jaeger_server() (string, error) {
    client := redisConnect()
    defer client.Close()
    return client.Get("clovisor_jaeger_server").Result()
}

func get_cfg_track_interfaces() ([]string, error) {
    client := redisConnect()
    defer client.Close()
    return client.LRange("clovior_track_interfaces", 0, -1).Result()
}

type WMConfig struct {
    Kind string `yaml:"kind"`
    Dest string `yaml:"dest"`
    Port string `yaml:"port"`
    User string `yaml:"user"`
    Wan struct {
        Srcintf string `yaml: "srcintf"`
        Interface string `yaml:"interface"`
        Srcip string `yaml:"srcip"`
        Dstip string `yaml:"dstip"`
        Dstport string `yaml:"dstport"`
        Smac string `yaml:"srcmac"`
        Dmac string `yaml:"dstmac"`
        Origmac string `yaml:"origmac"`
    } `yaml:"wan"`
}

type Wan struct {
    Srcintf string
    Interface string
    Srcip string
    Dstip string
    Dstport string
    Smac string
    Dmac string
    Origmac string
}

func set_wan_mapping(cfg *WMConfig) error {
    client := redisConnect()
    defer client.Close()
    //key := cfg.Kind + ";" + cfg.Dest + ";" + cfg.User
    key := cfg.Dest + ";" + cfg.Port + ";" + cfg.User
    wan := cfg.Wan
    value := wan.Interface + ";" + wan.Srcip + ";" + wan.Dstip + ";" + wan.Dstport + ";" + wan.Smac + ";" + wan.Dmac + ";" + wan.Origmac

    if _, err := client.HSet("clovisor_wan_mapping_cfg", key, value).Result(); err != nil {
        return err
    }
    return nil
}

func get_wan_mapping(kind string, dest string, user string) (*Wan, error) {
    client := redisConnect()
    defer client.Close()
    key := kind + ";" + dest + ";" + user

    if value, err := client.HGet("clovisor_wan_mapping_cfg", key).Result(); err != nil {
        return nil, err
    } else {
        val := strings.Split(value, ";")
        return &Wan{
                Srcintf: val[0],
                Interface: val[1],
                Srcip: val[2],
                Dstip: val[3],
                Dstport: val[4],
                Smac: val[5],
                Dmac: val[6],
                Origmac: val[7],
            }, nil
    }
}

func loadWANMapping(filename string) error {
    wanConfig := &WMConfig{}
    file, err := os.Open(filename)
    if err != nil {
        return err
    }
    defer file.Close()

    decoder := yaml.NewDecoder(file)

    if err := decoder.Decode(&wanConfig); err != nil {
        return err
    }

    // store in redis
    if err := set_wan_mapping(wanConfig); err != nil {
        return err
    }
    return nil
}

func Monitor_proto_plugin_cfg() {
    client := redisConnect()
    //defer client.Close()

    pubsub := client.Subscribe(clovisorCfgChan)
    //defer pubsub.Close()

    go func() {
        for {
            msg, err := pubsub.ReceiveMessage()
            if err != nil {
                fmt.Printf("Error getting clovisor configuration: %v\n", err)
                return
            }

            switch cfg := strings.Split(msg.Payload, ";"); cfg[0] {
                case "proto_plugin":
                    fmt.Printf("Update on protocol %v notification received\n", cfg[1])
                    loadProtoParser(cfg[1], true)
                case "redirect":
                    fmt.Printf("Redirect request: %v\n", cfg)
                    if cfg[1] == "add" {
                        setRedirectSession(cfg[1], cfg[2], cfg[3], cfg[4], cfg[5], cfg[6], cfg[7], cfg[8], cfg[9], cfg[10], cfg[11], cfg[12])
                    } else {
                        setRedirectSession(cfg[1], cfg[2], cfg[3], cfg[4], cfg[5], cfg[6], "", "", "", "", "", cfg[7])
                    }
                case "wan_mapping":
                    fmt.Printf("Loading file %v for WAN mapping...\n", cfg[1])
                    if err := loadWANMapping(cfg[1]); err != nil {
                        fmt.Printf("Error loading WAN mapping file %v: %v\n", cfg[1], err)
                    }
                default:
                    fmt.Printf("Incorrect config %v\n", cfg[0])
            }
        }
    }()
}
