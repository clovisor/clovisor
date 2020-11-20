// Copyright (c) Authors of Clover
//
// All rights reserved. This program and the accompanying materials
// are made available under the terms of the Apache License, Version 2.0
// which accompanies this distribution, and is available at
// http://www.apache.org/licenses/LICENSE-2.0

package clovisor

import (
	"fmt"
    "log"
	"net/http"
)

func redirectHandler(w http.ResponseWriter, r *http.Request) {
    switch r.Method {
    case "POST":
        if err := r.ParseForm(); err != nil {
            fmt.Printf("HTTP POST parsing error: %v\n", err)
            return
        }
        fmt.Printf("POST request: %v\n", r.PostForm)
        src_ip := r.FormValue("srcip")
        dst_ip := r.FormValue("dstip")
        src_port := r.FormValue("srcport")
        dst_port := r.FormValue("dstport")
        dest := r.FormValue("host")
        user := r.FormValue("user")

        val, err := get_wan_mapping(dest, dst_port, user)
        if err != nil {
            fmt.Printf("Fetch wan mapping failed: %v\n", err)
            return
        }
        // forward flow
        if err := setRedirectSession("add", val.Srcintf, val.Interface, src_ip, src_port, dst_ip, dst_port,
                                     val.Srcip, val.Dstip, val.Smac, val.Dmac, "1"); err != nil {
            fmt.Printf("Set redirection session for forward flow %v failed:%v\n", val, err)
            return
        }

        // reverse flow
        if err := setRedirectSession("add", val.Interface, val.Srcintf, dst_ip, dst_port, "", "",
                                     "", src_ip, "", val.Origmac, "0"); err != nil {
            fmt.Printf("Set redirection session for reverse flow %v failed:%v\n", val, err)
        }
    default:
        fmt.Printf("Unsupported HTTP method %v\n", r.Method)
    }
}

func ClovisorHttpServer() {
    go func(){
        http.HandleFunc("/redirect/", redirectHandler)
        log.Fatal(http.ListenAndServe(":8080", nil))
    }()
}
