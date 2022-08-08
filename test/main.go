package main

import (
	"log"

	"github.com/austinyono/test/block"
)

var testNumber = 20

func main() {
	log.Print(block.Hello)
	log.Panic(block.Hello)
}
