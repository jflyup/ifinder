package main

import (
	"errors"
	"regexp"
	"strings"
)

var modelList = map[string]string{
	"J1AP":   "iPad (3rd generation)",
	"J33AP":  "Apple TV (3rd generation), early 2012",
	"J33IAP": "revised version of the Apple TV (3rd generation), early 2013",
	"J42dAP": "Apple TV (4th generation)",
	"J71AP":  "Wifi only iPad Air",
	"J72AP":  "Cellular iPad Air",
	"J73AP":  "iPad Air",
	"J85AP":  "iPad mini 2",
	"J85mAP": "iPad mini 3",
	"J86AP":  "iPad mini 2",
	"J86mAP": "iPad mini 3",
	"J87AP":  "iPad mini 2",
	"J87mAP": "iPad mini 3",
	"J96AP":  "iPad mini 4",
	"J97AP":  "iPad mini 4",
	"J98aAP": "iPad Pro (12.9 inch) (iPad6,7 model)",
	"J99aAP": "iPad Pro (12.9 inch) (iPad6,8 model)",
	"K93AP":  "iPad 2",
	"K94AP":  "iPad 2",
	"P101AP": "iPad (4th generation)",
	"P105AP": "iPad mini",
	"P107AP": "iPad mini",
	// iPhones and iPods Apple Watches
	"N18AP":  "iPod touch 3G",
	"N27aAP": "Apple Watch 38mm (Watch1,1 model)",
	"N27dAP": "Apple Watch Series 1 38mm (Watch2,6 model)",
	"N28aAP": "Apple Watch 42mm (Watch1,2 model)",
	"N28dAP": "Apple Watch Series 1 42mm (Watch2,7 model)",
	"N41AP":  "iPhone 5",
	"N42AP":  "iPhone 5",
	"N45AP":  "first generation iPod touch",
	"N48AP":  "iPhone 5c",
	"N49AP":  "iPhone 5c",
	"N51AP":  "iPhone 5s",
	"N53AP":  "iPhone 5s",
	"N56AP":  "iPhone 6 Plus",
	"N61AP":  "iPhone 6",
	"N66AP":  "iPhone 6s Plus(with Samsung A9 processor)",
	"N66mAP": "N66mAP(with TSMC A9 processor)",
	"N69AP":  "iPhone SE(with TSMC A9 processo)",
	"N69uAP": "iPhone SE which uses the Samsung A9 processor",
	"N71AP":  "iPhone 6s which uses the Samsung A9 processor",
	"N71mAP": "iPhone 6s which uses the TSMC A9 processor",
	"N72AP":  "second generation iPod touch",
	"N74AP":  "Apple Watch Series 2 38mm (Watch2,3 model)",
	"N94AP":  "iPhone 4S",
	"N102AP": "iPod touch (6th generation)",
	"D101AP": "iPhone 7",
	"D10AP":  "iPhone 7",
	"D111AP": "iPhone 7 Plus",
	"D11AP":  "iPhone 7 Plus",
}

var services = []string{
	"_apple-mobdev2._tcp",
	"_afpovertcp._tcp",
	"_workstation._tcp",
	"_smb._tcp",
	"_rfb._tcp",
	"_homekit._tcp",
	"_sftp-ssh._tcp",
	"_ssh._tcp",
	"_http._tcp",
	"_gamecenter._tcp",
}

func queryiDeviceSpecs(txt string) (specs string) {
	if nPos := strings.Index(txt, "model="); nPos != -1 {
		model := txt[nPos+len("model="):]
		if v, ok := modelList[model]; ok {
			specs = v
		}
	}

	return
}

// trimDot removes all leading and trailing dots
func trimDot(s string) string {
	return strings.Trim(s, ".")
}

// becasue service instance name string may contain escaped dot, so we can't simply
// call strings.Split(name, ".")
func parseServiceName(name string) (instance, serviceType, domain string, err error) {
	s := trimDot(name)
	l := len(s)
	var ss []string
	for {
		pos := strings.LastIndex(s[:l], ".")
		if pos != -1 {
			ss = append(ss, s[pos+1:l])
			l = pos
			if len(ss) >= 3 {
				// done
				domain = ss[0]
				serviceType = ss[2] + "." + ss[1]
				instance = s[:l]
				break
			}
		} else {
			err = errors.New("illegal service instance")
			break
		}
	}

	return
}

// reverseIPv4 extract IPv4 from the reversed octets
// with special suffix in-addr.arpa (such as 4.3.2.1.in-addr.arpa)
func reverseIPv4(s string) string {
	words := strings.Split(s, ".")
	for i, j := 0, len(words)-1; i < j; i, j = i+1, j-1 {
		words[i], words[j] = words[j], words[i]
	}
	return strings.Join(words, ".")
}

// return true if s contain only letters, numbers, and hyphen
func checkInstanceName(s string) bool {
	alphaNumericHyphen := regexp.MustCompile(`^[-A-Za-z0-9]+$`).MatchString
	return alphaNumericHyphen(s)
}
