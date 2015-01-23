package main

// deploy usage:
//
//   deploy -mode "planetlab"|"zoo" -hosts "host1,host2" -config "cfg.json"
//
// hosts is a list of hostnames
// import "github.com/kolo/xmlrpc"

func main() {
	// if mode is planet lab: get a list of hostnames from the planetlab API
	// 		connect using xml-rpc
	//   or use given -hosts
	// read in a json config file
	// parse the config file into a valid tree replacing placeholder names with hostnames
	// write this finalized tree with the proper hostnames to a file
	// scp this file to the hosts (using proper authentication)
	// build the coco/exec for the target architectures
	// scp that file to the hosts
	// ssh run the file on each of the hosts
}
