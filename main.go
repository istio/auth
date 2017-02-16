package main

import (
	"flag"

	"istio.io/auth/controller"

	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
)

const configFile = "/home/yangguan/.kube/config"

func main() {
	flag.Parse()

	c, err := clientcmd.BuildConfigFromFlags("", configFile)
	if err != nil {
		panic(err)
	}

	cs, err := kubernetes.NewForConfig(c)
	if err != nil {
		panic(err)
	}

	snc := controller.NewSecureNamingController(cs.CoreV1())
	stopCh := make(chan struct{})
	snc.Run(stopCh)

	<-stopCh
}
