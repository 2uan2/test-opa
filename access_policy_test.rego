package rules.test

import data.rules

default allow := false

test_car_read_positive if {
	inp := {
		"method": "GET",
		"path": ["cars"],
		"user": "alice",
	}
	rules.allow with input as inp
}

test_car_read_negative if {
	inp := {
		"method": "GET",
		"path": ["foo"],
		"user": "alice",
	}
	not rules.allow with input as inp
}

test_car_create_positive if {
	inp = {
		"method": "POST",
		"path": ["cars"],
		"user": "charlie",
	}
	rules.allow with input as inp
}

test_car_create_negative if {
	inp = {
		"method": "POST",
		"path": ["cars"],
		"user": "alice",
	}
	not rules.allow with input as inp
}
