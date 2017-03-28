package main

import "strings"

var BoardConfigList = map[string]string{
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
	"D101AP": "iPhone 7",
	"D10AP":  "iPhone 7",
	"D111AP": "iPhone 7 Plus",
	"D11AP":  "iPhone 7 Plus",
}

var services = []string{"_apple-mobdev2._tcp",
	"_afpovertcp._tcp",
	"_workstation._tcp",
	"_smb._tcp",
	"_rfb._tcp",
	"_homekit._tcp",
}

func queryiDeviceType(txt string) string {
	typ := ""
	if nPos := strings.Index(txt, "model="); nPos != -1 {
		model := txt[nPos+6:]
		if name, ok := BoardConfigList[model]; ok {
			typ = name
		}
	}

	return typ
}

// trimDot is used to trim the dots from the start or end of a string
func trimDot(s string) string {
	return strings.Trim(s, ".")
}

func reverseIPv4(s string) string {
	words := strings.Split(s, ".")
	for i, j := 0, len(words)-1; i < j; i, j = i+1, j-1 {
		words[i], words[j] = words[j], words[i]
	}
	return strings.Join(words, ".")
}
