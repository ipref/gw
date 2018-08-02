/* Copyright (c) 2018 Waldemar Augustyn */

package main

func main() {

	parse_cli()
	log.set(cli.log_level, cli.stamps)

	log.info("start meadow")
	log.debug("some debugging message")
	log.trace("some trace message")
	log.err("some error message")
	log.info("finish meadow")
	log.fatal("some fatal exit message")
}
