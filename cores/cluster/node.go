package cluster

import "encoding/json"

// Node 节点信息
type Node interface {
	// 获取节点唯一编号
	ID() string

	// 获取节点所支持的协议
	Protocol() string

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
	Id           string `json:"id"`
	Addr         string `json:"address"`
	ProtocolName string `json:"protocol"`
	Values       map[string]string
}

func (n NodeLocal) ID() string {
	return n.Id
}

func (n NodeLocal) Protocol() string {
	return n.ProtocolName
}

func (n NodeLocal) Address() string {
	return n.Addr
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

func NewNode(id, protocol, address string) *NodeLocal {
	return &NodeLocal{
		Id:           id,
		ProtocolName: protocol,
		Addr:         address,
		Values:       make(map[string]string),
	}
}
