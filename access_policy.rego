package rules

default allow := false

users := {
	"alice": {"manager": "charlie", "title": "salesperson"},
	"bob": {"manager": "charlie", "title": "salesperson"},
	"charlie": {"manager": "dave", "title": "manager"},
	"dave": {"manager": null, "title": "ceo"},
}

user_is_employee if {
	users[input.user]
}

user_is_manager if {
	users[input.user].title != "salesperson"
}

allow if {
	input.method == "GET"
	input.path == ["cars"]
}

allow if {
	input.method == "POST"
	input.path == ["cars"]
	user_is_manager == true
}

allow if {
	input.method == "GET"

	[resource, car_id] := input.path
	resource == "cars"

	user_is_employee
}

allow if {
	input.method == "PUT"
	input.method == "DELETE"

	[resource, car_id] := input.path
	resource == "cars"

	user_is_manager
}
