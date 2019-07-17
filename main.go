package main

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/ioutil"
	"log"
	"net"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/codegangsta/cli"
	"github.com/syyongx/php2go"
)

// PackageHeader x
type PackageHeader struct {
	len     uint32
	protoid uint32
	cmd     uint16
	ret     int32
	userid  uint32
}

const hextable = "0123456789abcdef"

// Encode xx
func Encode(dstHex, dstChr, src []byte) {
	for i, v := range src {
		dstHex[i*3] = hextable[v>>4]
		dstHex[i*3+1] = hextable[v&0x0f]
		dstHex[i*3+2] = ' '
		if v >= 32 && v <= 126 {
			dstChr[i] = v
		} else {
			dstChr[i] = '.'
		}
	}
}

func printPkgJSON(data []byte, startPos int) {
	var showData = data[startPos:]
	var out bytes.Buffer
	err := json.Indent(&out, showData, "", "    ")
	if err != nil {
		log.Fatalln(err)
	}
	out.WriteTo(os.Stdout)
	fmt.Printf("\n")
}

func printPkg(data []byte, startPos int) {
	var showData = data[startPos:]
	var priLen = len(showData)
	var hexBuf = make([]byte, priLen*3)
	var chrBuf = make([]byte, priLen)
	Encode(hexBuf, chrBuf, showData)

	fmt.Printf("len[%3d]==========================================================================\n", priLen)
	var i = 0
	for i < priLen {
		var leftLen = priLen - i
		var FixLen8 = 0
		var FixLen16 = 0
		if leftLen >= 8 {
			FixLen8 = 0
		} else {
			FixLen8 = 8 - leftLen
		}
		if leftLen >= 16 {
			FixLen16 = 0
		} else {
			FixLen16 = 16 - leftLen
		}
		fmt.Printf("%d\t %-24s  %-24s   %-8s %-8s\n",
			startPos+i,
			hexBuf[i*3:i*3+24-FixLen8*3],
			hexBuf[i*3+24-FixLen8*3:i*3+48-FixLen16*3],
			chrBuf[i:i+8-FixLen8],
			chrBuf[i+8-FixLen8:i+16-FixLen16])

		i = i + 16
	}
	fmt.Printf("end:==============================================================================\n")

	/*
		msg=bin2hex_2(msg)
		pri_len=len(msg)/2
		i=0
		print ""% (pri_len)
		phex=re.compile(r'(\w\w)')
		while(i<pri_len):
			hex_msg=phex.sub(r"\1 ", msg[i*2:(i+16)*2]);
			chr_msg=phex.sub(get_chr_ex , msg[i*2:(i+16)*2]);
			print "\t%d\t %-24s %-24s  %-8s %-8s"	%(startid+ i,
					hex_msg[0:24], hex_msg[24:48],
					chr_msg[0:8], chr_msg[8:16] )
			i=i+16;
		print "end:=================================================================================="
	*/
}

func sendData(ipport string, data []byte) []byte {
	fmt.Printf("sendto:%s\n", ipport)
	conn, err := net.Dial("tcp", ipport)
	defer conn.Close()
	if err != nil {
		panic(err.Error())
	}

	_, err = conn.Write(data)

	var buf = make([]byte, 0, 20)
	var tmpBuf = make([]byte, 1)
	var maxLen = 0xFFFFFFFF
	var needReadLen = maxLen
	var readLen = 0

	for readLen < needReadLen {
		tmpReadLen, tmpErr := conn.Read(tmpBuf)
		if err != nil {
			panic(tmpErr.Error())
		}
		readLen += tmpReadLen
		buf = Append(buf, tmpBuf[0:tmpReadLen])

		if needReadLen == maxLen && readLen >= 4 {
			needReadLen = int(binary.LittleEndian.Uint32(buf))
		}
	}
	return buf
}

func sendf(ip string, port int, args []string) {

	var hexbuf = strings.Join(args, "")
	var hexbufLen = len(hexbuf)
	if hexbufLen%2 == 1 {
		fmt.Println("hex buf len need 2n ")
		return
	}
	var sendBinbuf = make([]byte, hexbufLen/2)
	var err error
	_, err = hex.Decode(sendBinbuf, []byte(hexbuf))
	if err != nil {
		//	fmt.Println("hex buf len need [0-9a-f]")
		println(err.Error())
		return
		//panic(err.Error())
	}

	var ipport = ip + ":" + strconv.Itoa(port)
	var buf = sendData(ipport, sendBinbuf)

	//show outbuf
	var ph = new(PackageHeader)

	var buffer = bytes.NewBuffer(buf)

	getData(buffer, &ph.len)
	getData(buffer, &ph.protoid)
	getData(buffer, &ph.cmd)
	getData(buffer, &ph.ret)
	getData(buffer, &ph.userid)

	fmt.Printf("len:\t%d\n", ph.len)
	fmt.Printf("cmd:\t%04X\n", ph.cmd)
	fmt.Printf("protoid:%d\n", ph.protoid)
	fmt.Printf("ret:\t%d\n", ph.ret)
	fmt.Printf("userid:\t%d\n", ph.userid)
	printPkgJSON(buf, 18)
}

func getByteOrder(bigEndlianFlag bool) binary.ByteOrder {
	if bigEndlianFlag {
		return binary.BigEndian
	}
	return binary.LittleEndian
}

func cx(bigEndlianFlag bool, Args []string) {

	var value, err = strconv.Atoi(Args[0])
	if err != nil {
		println(err.Error())
		return
	}

	var valbuf = make([]byte, 4)
	var hexbuf = make([]byte, 8)
	getByteOrder(bigEndlianFlag).PutUint32(valbuf, uint32(value))
	hex.Encode(hexbuf, valbuf)
	fmt.Printf("%s\n", hexbuf)

}

type fileInfo struct {
	SuccFlag bool
	FuncList []string
}

func getCmdlist(protoDir string) []string {

	cmdList := []string{}
	dir, err := ioutil.ReadDir(protoDir)
	if err != nil {
		fmt.Printf("扫描文件夹出错:%s\n", protoDir)
		return cmdList
	}

	for _, fileinfo := range dir {
		fileName := fileinfo.Name()
		arr := strings.Split(fileName, ".")
		if len(arr) == 2 {
			base := arr[0]
			ext := arr[1]
			if ext == "proto" {
				if strings.Index(base, "__") > 0 {
					cmdList = append(cmdList, base)
				}
			}
		}

	}
	return cmdList

}

func genCtrl(Args []string) {

	cmdList := getCmdlist(Args[0])

	//jsondata := spew.Sdump(cmdList)
	//fmt.Printf("===%s\n", jsondata)
	ctrlDir := Args[1]

	dir, err := ioutil.ReadDir(ctrlDir)
	if err != nil {
		fmt.Printf("扫描文件夹出错:%s\n", ctrlDir)
		return
	}

	fileinfo := map[string]fileInfo{}
	for _, filename := range dir {
		filePath := ctrlDir + "/" + filename.Name()

		fset := token.NewFileSet() // positions are relative to fset
		file, err := parser.ParseFile(fset, filePath, nil, parser.ParseComments)

		fileItem := fileInfo{}
		if err != nil {
			fileItem.SuccFlag = false
			fileinfo[filePath] = fileItem
			continue
		}

		fileItem.SuccFlag = true
		for _, decl := range file.Decls {
			funcDecl, ok := decl.(*ast.FuncDecl)
			if ok {
				fileItem.FuncList = append(fileItem.FuncList, funcDecl.Name.Name)
				/*
					if len(funcDecl.Recv.List) == 1 {
						ctrl, ok := funcDecl.Recv.List[0].Type.(*ast.StarExpr)
						if ok {

							_, ok := ctrl.X.(*ast.Ident)
							if ok {
								//fmt.Printf("\"%s %s\n", indent.Name, funcDecl.Name)
							}

						}
					}
				*/

				//data := spew.Sdump(funcDecl)

			}
		}
		fileinfo[strings.Split(filename.Name(), ".")[0]] = fileItem
	}
	//data, err := json.Marshal(fileinfo)
	//fmt.Printf(" %s\n", data)
	//生成 代码到目标文件
	genCtrlCode(ctrlDir, cmdList, fileinfo)

}
func genCtrlCode(ctrlDir string, cmdList []string, fileinfo map[string]fileInfo) {

	for _, cmd := range cmdList {
		arr := strings.Split(cmd, "__")
		ctrl := arr[0]
		action := arr[1]
		camelAction := CamelString(action)
		camelCtrl := CamelString(ctrl)
		filename := ctrlDir + "/" + ctrl + ".go"
		filedata, _ := php2go.FileGetContents(filename)
		if filedata == "" {
			fmt.Printf("gen %s\n", filename)
			genCtrlBaseFile(filename, ctrl)
		}
		ctrlInfo, ok := fileinfo[ctrl]
		genActionFlag := false
		if ok {
			if ctrlInfo.SuccFlag {
				if !php2go.InArray(camelAction, ctrlInfo.FuncList) {
					genActionFlag = true
				}
			}
		} else {
			genActionFlag = true
		}
		if genActionFlag {
			fmt.Printf("gen action %s %s \n", filename, action)

			actionStr := `
// ` + camelAction + ` xx
func (m * ` + camelCtrl + `)  ` + camelAction + `(ctx context.Context, in *proto.` + camelCtrl + camelAction + `In, out *proto.` + camelCtrl + camelAction + `Out ) (interface{}, error) {

	return m.outputErr(" ` + camelCtrl + camelAction + `生成代码未实现")
}`
			fd, _ := os.OpenFile(filename, os.O_RDWR|os.O_APPEND, 0644)
			fd.Write([]byte(actionStr))
			fd.Close()

		}

		//ioutil.  (filename, []byte(str), 0644)
	}

}

// CamelString  转驼峰 camel string, xx_yy to XxYy
func CamelString(s string) string {
	data := make([]byte, 0, len(s))
	j := false
	k := false
	num := len(s) - 1
	for i := 0; i <= num; i++ {
		d := s[i]
		if k == false && d >= 'A' && d <= 'Z' {
			k = true
		}
		if d >= 'a' && d <= 'z' && (j || k == false) {
			d = d - 32
			j = false
			k = true
		}
		if k && d == '_' && num > i && s[i+1] >= 'a' && s[i+1] <= 'z' {
			j = true
			continue
		}
		data = append(data, d)
	}
	return string(data[:])
}

func genCtrlBaseFile(filename string, ctrl string) {
	camelCtrl := CamelString(ctrl)
	str := `package controllers

import (
	"context"
	"server/gen/proto"

	"github.com/TarsCloud/TarsGo/tars/util/set"
)

// ` + camelCtrl + ` x
type ` + camelCtrl + ` struct {
	Controller
}

// CheckLoginFlag x
func (m *` + camelCtrl + `) CheckLoginFlag() bool {
	return true
}

// GetNoNeedCheckLoginActionMap  x
func (m *` + camelCtrl + `) GetNoNeedCheckLoginActionMap() *set.Set {
	//return set.NewSet("action_name" )
	return set.NewSet()
}`

	ioutil.WriteFile(filename, []byte(str), 0644)
}

func lsf(Args []string) {
	var fileName, err = filepath.Abs(Args[0])
	if err != nil {
		println(err.Error())
		return
	}
	fmt.Printf("%s\n", fileName)

}

func sf(startPos int, Args []string) {

	var hexbuf = strings.Join(Args, "")
	var binbuf = make([]byte, len(hexbuf)/2)
	var _, err = hex.Decode(binbuf, []byte(hexbuf))
	if err != nil {
		panic(err.Error())
	}
	printPkg(binbuf, startPos)

}

func cint(bigEndlianFlag bool, notUnsignedFlag bool, Args []string) {

	var hexbuf = strings.Join(Args, "")
	var defbuf = "00000000"
	var valbuf = make([]byte, 4)
	if len(hexbuf) <= 8 {
		hexbuf = defbuf[0:8-len(hexbuf)] + hexbuf
		hex.Decode(valbuf, []byte(hexbuf))
		var val uint32
		val = getByteOrder(bigEndlianFlag).Uint32(valbuf)

		if notUnsignedFlag {
			fmt.Printf("%d\n", int32(val))
		} else {
			fmt.Printf("%d\n", val)
		}

	} else {
		fmt.Print("need 8 chars\n")
	}
}

// CmdInfo x
type CmdInfo struct {
	Name       string
	ExecHandle func([]string)
}

func main() {

	app := cli.NewApp()
	app.Name = "nettool"
	app.Usage = "make an explosive entrance"
	app.Version = "0.1.1"
	app.EnableBashCompletion = true

	app.Commands = []cli.Command{
		{
			Name: "cint",
			//			Aliases: []string{"a"},
			Usage: "cint",
			Flags: []cli.Flag{
				cli.BoolFlag{
					Name:  "big-endlian, b",
					Usage: "big-endlian",
					//EnvVar: "APP_LANG",
				},
				cli.BoolFlag{
					Name:  "not-unsigned, n",
					Usage: "not unsigned",
					//EnvVar: "APP_LANG",
				},
			},

			Action: func(c *cli.Context) {
				cint(c.Bool("big-endlian"), c.Bool("not-unsigned"), c.Args())
			},
		}, {
			Name: "cx",
			//			Aliases: []string{"a"},
			Usage: "cx",
			Flags: []cli.Flag{
				cli.BoolFlag{
					Name:  "big-endlian, b",
					Usage: "big-endlian",
					//EnvVar: "APP_LANG",
				},
			},

			Action: func(c *cli.Context) {
				cx(c.Bool("big-endlian"), c.Args())
			},
		}, {
			Name: "lsf",
			//			Aliases: []string{"a"},
			Usage: "lsf",
			Flags: []cli.Flag{
				cli.BoolFlag{},
			},

			Action: func(c *cli.Context) {
				lsf(c.Args())
			},
		},

		{
			Name: "sf",
			//			Aliases: []string{"a"},
			Usage: "sf",
			Flags: []cli.Flag{
				cli.IntFlag{
					Name:  "start-pos, s",
					Usage: "start pos",
					//EnvVar: "APP_LANG",
				},
			},

			Action: func(c *cli.Context) {
				sf(c.Int("start-pos"), c.Args())
			},
		},
		{

			Name: "getdate",
			//			Aliases: []string{"a"},
			Usage: "getdate",
			Action: func(c *cli.Context) {
				var unixTime, _ = strconv.Atoi(c.Args()[0])
				var tm = time.Unix(int64(unixTime), 0)
				fmt.Println(tm.Format("2006-01-02 15:04:05"))
			},
		}, {
			Name: "genctrl",
			//			Aliases: []string{"a"},
			Usage: "genctrl",

			Action: func(c *cli.Context) {
				genCtrl(c.Args())
			},
		}, {
			Name: "sendf",
			//			Aliases: []string{"a"},
			Usage: "sendf 16 00 00 00 C9 00 0C 00 50 10 00 00 00 00 58 C3 00 00 00 00 00 00",
			/*
				flag.StringVar(&ip, "h", "192.168.0.3", "test server ip ")
				flag.IntVar(&port, "p", 23332, "test server port")
			*/

			Flags: []cli.Flag{
				cli.StringFlag{
					Name:  "host, H",
					Usage: "host",
					Value: "127.0.0.1",
					//EnvVar: "APP_LANG",
				},
				cli.IntFlag{
					Name:  "port, p",
					Usage: "port",
					Value: 23001,
					//EnvVar: "APP_LANG",
				},
			},

			Action: func(c *cli.Context) {
				sendf(c.String("host"), c.Int("port"), c.Args())
			},
		},
	}

	var cmdname = path.Base(os.Args[0])

	var addFixCommandFlag = false
	for _, item := range app.Commands {
		if cmdname == item.Name {
			addFixCommandFlag = true
			break
		}
	}

	var args []string

	if addFixCommandFlag {
		args = []string{
			"nettool",
		}
		for i, arg := range os.Args {
			if i == 0 {
				args = append(args, cmdname)
			} else {
				args = append(args, arg)
			}
		}

	} else {
		args = os.Args
	}

	app.Run(args)

}

func getData(buffer *bytes.Buffer, data interface{}) {
	binary.Read(buffer, binary.LittleEndian, data)
}

// Append xx
func Append(slice, data []byte) []byte {
	l := len(slice)
	if l+len(data) > cap(slice) { // reallocate
		// Allocate double what's needed, for future growth.
		newSlice := make([]byte, (l+len(data))*2)
		// The copy function is predeclared and works for any slice type.
		copy(newSlice, slice)
		slice = newSlice
	}

	slice = slice[0 : l+len(data)]

	copy(slice[l:], data)
	/*
		for i, c := range data {
			slice[l+i] = c
		}
	*/
	return slice
}
