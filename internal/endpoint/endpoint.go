package endpoint

// Configuration 配置文件
type Configuration struct {
	ID   string `yaml:"id" json:"id" usage:"节点唯一编号"`
	Name string `yaml:"name" json:"name" usage:"节点唯一名称"`
}
