/* Copyright (c) 2018 Waldemar Augustyn */

package main

import (
	"testing"
)

type RefData struct {
	ref string
	res bool
}

// Test regular expressions validating reference formats
func TestReferenceRegex(t *testing.T) {

	compile_regex()

	// false means bad reference, true means good reference

	// hex references

	hex_refs := []RefData{
		{"44--55", false},
		{"123 45", false},
		{"abC-12-3456", true},
		{"0123-", false},
		{"-123", false},
		{"", false},
		{"00-000-123", true},
		{"12-345-7689-abc-def-ABCD-EF", true},
		{"12.3", false},
		{"12,a3", false},
		{"1", true},
		{"1g", false},
		{"2G", false},
		{"F", true},
		{"0", true},
		{"65536", true},
		{" a652", false},
		{"652a ", false},
	}

	for _, data := range hex_refs {

		if re_hexref.MatchString(data.ref) != data.res {
			t.Errorf("hex reference |%v| fails", data.ref)
		}
	}

	// decimal references

	dec_refs := []RefData{
		{"12:44", false},
		{"12,44", true},
		{"0,12,441", true},
		{"12,0441", true},
		{"012,441", true},
		{"0", false},
		{"0,0", true},
		{"000,00000000,0000,0", true},
		{" 128", false},
		{"128 ", false},
		{"17,", false},
		{",887", false},
		{"123478,1242412,1242899874", true},
		{"", false},
	}

	for _, data := range dec_refs {

		if re_decref.MatchString(data.ref) != data.res {
			t.Errorf("decimal reference |%v| fails", data.ref)
		}
	}

	// dotted decimal references

	dot_refs := []RefData{
		{"1.2.3.4", true},
		{"101.2.3.4", true},
		{"100.2.3.4", true},
		{"99.2.3.4", true},
		{"9.2.3.4", true},
		{"0.0.0.0.0.0.0", true},
		{"1.02.3.4", false},
		{"1.2.323.4", false},
		{"1.2.3.4.5.0.10.100.200.249.250.255.79.187", true},
		{"1.23.4", true},
		{"0.249", true},
		{"0.199.250", true},
		{"199.250", true},
		{"255.7", true},
		{"128", false},
		{"1.256.3.4", false},
		{"1.2.b.4", false},
		{"0.246.3.4", true},
		{"00.2.3.4", false},
		{"123.2.3.4.", false},
		{".12.2.3.4", false},
		{"", false},
		{" 2.2.3.4", false},
		{"1.2.3.4 ", false},
	}

	for _, data := range dot_refs {

		if re_dotref.MatchString(data.ref) != data.res {
			t.Errorf("dotted reference |%v| fails", data.ref)
		}
	}
}
