package cluster

// Node 节点信息
type Node interface {
	ID() string
}

type NodeLocal struct {
	Id       string `json:"id"`
	Address  string `json:"address"`
	Protocol string `json:"protocol"`
}

func (n NodeLocal) ID() string {
	return n.Id
}

func NewNodeLocal(id string) *NodeLocal {
	return &NodeLocal{
		Id: id,
	}
}
