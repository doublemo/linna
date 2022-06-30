package cluster

import "encoding/json"

// Node 节点信息
type Node interface {
	// 获取节点唯一编号
	ID() string

	// 获取节点所支持的协议
	Protocol() Protocol

	// 节点服务名称
	Service() string

	// 是否为子服务
	Sub() bool

	// 获取节点的地址以及服务商品
	Address() string

	// 获取节点中附加的参数信息
	Value(k string) (string, bool)

	// 设置节点的附加信息
	SetValue(k, v string)

	// 编码节点信息
	Marshal() (string, error)

	// 解码节点信息
	Unmarshal(s string) error
}

type NodeLocal struct {
	Id           string   `json:"id"`
	Name         string   `json:"name"`
	Addr         string   `json:"address"`
	ProtocolName Protocol `json:"protocol"`
	IsSub        bool
	Values       map[string]string
}

func (n NodeLocal) ID() string {
	return n.Id
}

func (n NodeLocal) Protocol() Protocol {
	return n.ProtocolName
}

func (n NodeLocal) Service() string {
	return n.Name
}

func (n NodeLocal) Address() string {
	return n.Addr
}

func (n NodeLocal) Sub() bool {
	return n.IsSub
}

func (n *NodeLocal) Value(k string) (string, bool) {
	v, ok := n.Values[k]
	return v, ok
}

func (n *NodeLocal) SetValue(k, v string) {
	n.Values[k] = v
}

func (n *NodeLocal) Marshal() (string, error) {
	data, err := json.Marshal(n)
	if err != nil {
		return "", err
	}

	return string(data), nil
}

func (n *NodeLocal) Unmarshal(data string) error {
	return json.Unmarshal([]byte(data), n)
}

func NewNode(id string, protocol Protocol, address string) *NodeLocal {
	return &NodeLocal{
		Id:           id,
		Name:         "linna",
		ProtocolName: protocol,
		Addr:         address,
		Values:       make(map[string]string),
		IsSub:        false,
	}
}

func NewSubNode(id, name string, protocol Protocol, address string) *NodeLocal {
	return &NodeLocal{
		Id:           id,
		ProtocolName: protocol,
		Addr:         address,
		Values:       make(map[string]string),
		IsSub:        true,
	}
}
