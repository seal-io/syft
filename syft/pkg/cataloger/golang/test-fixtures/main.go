package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"

	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var addr = flag.String("http-port", ":8080", "The address to listen on for HTTP requests.")

func main() {
	flag.Parse()

	awsSecret := "AKIAIMNOJVGFDXXXE4OA"
	fmt.Println("add aws secret leak:", awsSecret)

	fmt.Println("starting prometheus metric server")
	http.Handle("/metrics", promhttp.Handler())
	log.Fatal(http.ListenAndServe(*addr, nil))
}
