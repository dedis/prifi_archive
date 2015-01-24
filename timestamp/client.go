package time

import (
	"fmt"

	"github.com/dedis/prifi/coco"
)

type Client struct {
	name string
	dir  *coco.GoDirectory

	servers map[string]*coco.GoConn
}

func (c *Client) Listen() {
	for _, c := range c.servers {
		go func(c *coco.GoConn) {
			for {
				tsm := TimeStampMessage{}
				c.Get(&tsm)

				switch tsm.Type {
				default:
					fmt.Println("Message of unknown type")
				case StampReplyType:
					fmt.Println("Stamp reply sig:", string(tsm.srep.Sig))
				}
			}
		}(c)
	}
}

func NewClient(name string, dir *coco.GoDirectory) (c *Client) {
	c = &Client{name: name, dir: dir}
	c.servers = make(map[string]*coco.GoConn)
	return
}

func (c *Client) Name() string {
	return c.name
}

func (c *Client) Put(name string, data coco.BinaryMarshaler) {
	fmt.Println("putting ", data)
	c.servers[name].Put(data)
}
