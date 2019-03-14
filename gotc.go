package gotc

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"os/exec"
	"regexp"
	"strconv"
)

var strCreateClass string
var strCreateFilter string
var strShowFilter string
var strDeleteFilter string
var strDeleteClass string
var regexpMatchIP string

func initCmdForIpv4() {
	rsID := ".*fh (\\w+::\\w+) .*flowid (\\w+:\\w+) *\n *"
	rsMatch := "[\t ]+match (.*) at (\\d+) *\n *"
	regexpMatchIP = rsID + rsMatch

	strCreateClass = "tc class add dev %s parent %x: classid %x:%x htb rate %s burst %s"
	strCreateFilter = "tc filter add dev %s protocol ip parent 1:0 prio 1 u32 match ip src %s flowid %x:%x"
	strShowFilter = "tc filter show dev %s"
	strDeleteFilter = "tc filter delete dev %s parent %x: protocol ip prio 1 handle %s u32"
	strDeleteClass = "tc class del dev %s parent %x: classid %s"
}

func initCmdForIpv6() {
	rsID := ".*fh (\\w+::\\w+) .*flowid (\\w+:\\w+) *\n *"
	rsMatch := "[\t ]+match (.*) at (\\d+) *\n *"
	regexpMatchIP = rsID + rsMatch + rsMatch + rsMatch + rsMatch

	strCreateClass = "tc class add dev %s parent %x: classid %x:%x htb rate %s burst %s"
	strCreateFilter = "tc filter add dev %s protocol ipv6 parent 1:0 prio 1 u32 match ip6 src %s flowid %x:%x"
	strShowFilter = "tc filter show dev %s"
	strDeleteFilter = "tc filter delete dev %s parent %x: protocol ipv6 prio 1 handle %s u32"
	strDeleteClass = "tc class del dev %s parent %x: classid %s"
}

// cmdForShell run a bash command
// @cmdStr:
func cmdForShell(cmdStr string) (string, error) {
	cmd := exec.Command("sh", "-c", cmdStr)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()

	outStr, _ := string(stdout.Bytes()), string(stderr.Bytes())
	if err != nil {
		return outStr, err
	}

	return outStr, nil
}

func getParentFlowid(input string) (uint64, uint64, error) {
	r, err := regexp.Compile(".*(\\w+):(\\w+).*")
	if err != nil {
		return 0, 0, err
	}

	if match := r.FindStringSubmatch(input); match != nil && len(match) == 3 {
		parent, _ := strconv.ParseUint(match[1], 16, 64)
		classid, _ := strconv.ParseUint(match[2], 16, 64)

		return parent, classid, nil
	}
	return 0, 0, errors.New("get failed")
}

func match2Ip(input []string) string {
	var out string
	r, err := regexp.Compile("(\\w{2})(\\w{2})(\\w{2})(\\w{2})/(\\w{2})(\\w{2})(\\w{2})(\\w{2})")
	if err != nil {
		return ""
	}

	if len(input) == 8 { // IPv6
		for _, m := range input {
			if match := r.FindAllStringSubmatch(m, -1); match != nil {
				lst := match[0]
				ip1, _ := strconv.ParseUint(lst[1]+lst[2], 16, 16)
				ip2, _ := strconv.ParseUint(lst[3]+lst[4], 16, 16)
				msk1, _ := strconv.ParseUint(lst[5]+lst[6], 16, 16)
				msk2, _ := strconv.ParseUint(lst[7]+lst[8], 16, 16)

				ip1 = ip1 & msk1
				ip2 = ip2 & msk2

				sip1 := strconv.FormatUint(ip1, 16)
				sip2 := strconv.FormatUint(ip2, 16)

				if sip1 == "0" {
					sip1 = ""
				}

				if sip2 == "0" {
					sip2 = ""
				}

				if sip1 == "" && sip2 == "" {
					out += ":"
				} else {
					out += sip1 + ":" + sip2 + ":"
				}
			}
		}
		out = out[:len(out)-1] // Cut last ':' or '.'
	} else { // IPv4
		for _, m := range input {
			if match := r.FindAllStringSubmatch(m, -1); match != nil {
				lst := match[0]
				ip1, _ := strconv.ParseUint(lst[1], 16, 16)
				ip2, _ := strconv.ParseUint(lst[2], 16, 16)
				ip3, _ := strconv.ParseUint(lst[3], 16, 16)
				ip4, _ := strconv.ParseUint(lst[4], 16, 16)
				msk1, _ := strconv.ParseUint(lst[5], 16, 16)
				msk2, _ := strconv.ParseUint(lst[6], 16, 16)
				msk3, _ := strconv.ParseUint(lst[7], 16, 16)
				msk4, _ := strconv.ParseUint(lst[8], 16, 16)

				ip1 = ip1 & msk1
				ip2 = ip2 & msk2
				ip3 = ip3 & msk3
				ip4 = ip4 & msk4

				sip1 := strconv.FormatUint(ip1, 10)
				sip2 := strconv.FormatUint(ip2, 10)
				sip3 := strconv.FormatUint(ip3, 10)
				sip4 := strconv.FormatUint(ip4, 10)

				out = sip1 + "." + sip2 + "." + sip3 + "." + sip4
			}
		}
	}

	return out
}

// createQdisc - Create qdisc with a number
func createQdisc(dev string) (uint64, error) {
	var i uint64

	for i = 1; i <= 0xffff; i++ {
		cmdCreateQdisc := fmt.Sprintf("tc qdisc add dev %s root handle %x: htb", dev, i)
		ret, err := cmdForShell(cmdCreateQdisc)
		if err != nil {
			continue
		}
		if len(ret) == 0 {
			return i, nil
		}
	}

	return 0, errors.New("Create qdisc failed!")
}

// getParentID - Get qdisc htb id
func getParentID(dev string) (id uint64, err error) {
	cmdShowParent := fmt.Sprintf("tc qdisc show dev %s", dev)
	/* The result is like this:
	 * qdisc htb 1: root refcnt 5 r2q 10 default 0 direct_packets_stat 18
	 */
	ret, err := cmdForShell(cmdShowParent)
	if err != nil {
		fmt.Println(cmdShowParent)
		return 0, err
	}

	r, err := regexp.Compile(".*qdisc.*htb (\\w+):.*")
	if err != nil {
		return 0, err
	}
	match := r.FindStringSubmatch(ret)
	if match == nil {
		id, err = createQdisc(dev)
		if err != nil {
			return 0, err
		}
	} else {
		id, _ = strconv.ParseUint(match[1], 16, 64)
	}

	return id, nil
}

// createClass - Create class with a number
func createClass(parentID uint64, limit, burst, dev string) (uint64, error) {
	// The counter start at 1, because the 0 is a blank in tc result
	var i uint64
	for i = 1; i <= 0xffff; i++ {
		cmdCreateClass := fmt.Sprintf(
			strCreateClass,
			dev, parentID, parentID, i, limit, burst)

		/* The failed result is:
		 * "RTNETLINK answers: File exists" or "Error: argument "1:fffff" is wrong: invalid class ID"
		 */
		ret, err := cmdForShell(cmdCreateClass)
		if err != nil {
			continue
		}
		if len(ret) == 0 {
			return i, nil
		}
	}
	return 0, errors.New("Create class failed")
}

// createFilter - Create filter with a number
func createFilter(ip, limit, burst, dev string) error {
	parentID, err := getParentID(dev)
	if err != nil {
		return err
	}

	classID, err := createClass(parentID, limit, burst, dev)
	if err != nil {
		return err
	}

	cmdCreateFilter := fmt.Sprintf(
		strCreateFilter,
		dev, ip, parentID, classID)
	_, err = cmdForShell(cmdCreateFilter)
	if err != nil {
		return err
	}

	return nil
}

// deleteFilter - delete the tc filter item corresponding to the ip
func deleteFilter(ip, dev string) error {
	cmdShowFilter := fmt.Sprintf(strShowFilter, dev)
	/* The result is like this:
	 *
	 * filter parent 1: protocol ipv6 pref 1 u32
	 * filter parent 1: protocol ipv6 pref 1 u32 fh 800: ht divisor 1
	 * filter parent 1: protocol ipv6 pref 1 u32 fh 800::800 order 2048 key ht 800 bkt 0 flowid 1:1
	 *   match 2a4b5d9c/ffffffff at 8
	 *   match 8c029c92/ffffffff at 12
	 *   match 00000000/ffffffff at 16
	 *   match 93849580/ffffffff at 20
	 * filter parent 1: protocol ipv6 pref 1 u32 fh 800::801 order 2049 key ht 800 bkt 0 flowid 1:2
	 *   match 22222220/ffffffff at 8
	 *   match 33333337/ffffffff at 12
	 *   match 44444440/ffffffff at 16
	 *   match 66666664/ffffffff at 20
	 */
	ret, err := cmdForShell(cmdShowFilter)
	if err != nil {
		return err
	}

	r, err := regexp.Compile(regexpMatchIP)
	if err != nil {
		return err
	}
	match := r.FindAllStringSubmatch(ret, -1)

	for _, j := range match {
		fh := j[1]
		flowid := j[2]
		parentid, _, err := getParentFlowid(flowid)
		if err != nil {
			return err
		}

		if ip == match2Ip(j[3:]) {
			cmdDeleteFilter := fmt.Sprintf(
				strDeleteFilter,
				dev, parentid, fh)
			_, err = cmdForShell(cmdDeleteFilter)
			if err != nil {
				fmt.Println(cmdDeleteFilter)
				return err
			}
			cmdDeleteClass := fmt.Sprintf(
				strDeleteClass,
				dev, parentid, flowid)
			_, err = cmdForShell(cmdDeleteClass)
			if err != nil {
				fmt.Println(cmdDeleteClass)
				return err
			}
		}
	}

	return nil
}

// GetNetDev - get network device by ip address
func GetNetDev(ip string) (string, error) {
	inf, err := net.Interfaces()
	if err != nil {
		return "", errors.New("Can't read network device")
	}
	for _, dev := range inf {
		addrs, err := dev.Addrs()
		if err != nil {
			return "", errors.New("Can't read ip in " + dev.Name)
		}

		for _, addr := range addrs {
			saddr := addr.String()
			dest, _, err := net.ParseCIDR(saddr)
			if err != nil {
				continue
			}
			if dest.String() == ip || saddr == ip {
				return dev.Name, nil
			}
		}
	}
	return "", errors.New("No this ip")
}

// DeleteClass - delete the filter with class by ip address
func DeleteClass(ip string) error {
	initCmdForIpv4()

	dev, err := GetNetDev(ip)
	if err != nil {
		return err
	}

	return deleteFilter(ip, dev)
}

// DeleteClassIpv6 - delete the filter with class by ipv6 address
func DeleteClassIpv6(ip string) error {
	initCmdForIpv6()

	dev, err := GetNetDev(ip)
	if err != nil {
		return err
	}

	return deleteFilter(ip, dev)
}

// SetBandWidthLimit - Set bandwidth with ipv4 address
func SetBandWidthLimit(ip, limit, burst string) error {
	initCmdForIpv4()

	dev, err := GetNetDev(ip)
	if err != nil {
		return err
	}

	err = deleteFilter(ip, dev)
	if err != nil {
		return err
	}

	return createFilter(ip, limit, burst, dev)
}

// SetBandWidthLimitIpv6 - Set bandwidth with ipv6 address
func SetBandWidthLimitIpv6(ip, limit, burst string) error {
	initCmdForIpv6()

	dev, err := GetNetDev(ip)
	if err != nil {
		return err
	}

	err = deleteFilter(ip, dev)
	if err != nil {
		return err
	}

	return createFilter(ip, limit, burst, dev)
}
