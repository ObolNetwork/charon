// Copyright © 2022-2025 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package cmd

// generator used - https://patorjk.com/software/taag/#p=display&f=Big

func peersASCII() []string {
	return []string{
		"  ____                                                          ",
		" |  __ \\                                                        ",
		" | |__) |___   ___  _ __  ___                                   ",
		" |  ___// _ \\ / _ \\| '__|/ __|                                  ",
		" | |   |  __/|  __/| |   \\__ \\                                  ",
		" |_|    \\___| \\___||_|   |___/                                  ",
	}
}

func beaconASCII() []string {
	return []string{
		"  ____                                                          ",
		" |  _ \\                                                         ",
		" | |_) |  ___   __ _   ___  ___   _ __                          ",
		" |  _ <  / _ \\ / _` | / __|/ _ \\ | '_ \\                         ",
		" | |_) ||  __/| (_| || (__| (_) || | | |                        ",
		" |____/  \\___| \\__,_| \\___|\\___/ |_| |_|                        ",
	}
}

func validatorASCII() []string {
	return []string{
		" __      __     _  _      _         _                           ",
		" \\ \\    / /    | |(_,    | |       | |                          ",
		"  \\ \\  / /__ _ | | _   __| |  __ _ | |_  ___   _ __             ",
		"   \\ \\/ // _` || || | / _` | / _` || __|/ _ \\ | '__|            ",
		"    \\  /| (_| || || || (_| || (_| || |_| (_) || |               ",
		"     \\/  \\__,_||_||_| \\__,_| \\__,_| \\__|\\___/ |_|               ",
	}
}

func mevASCII() []string {
	return []string{
		" __  __ ________      __                                        ",
		"|  \\/  |  ____\\ \\    / /                                        ",
		"| \\  / | |__   \\ \\  / /                                         ",
		"| |\\/| |  __|   \\ \\/ /                                          ",
		"| |  | | |____   \\  /                                           ",
		"|_|  |_|______|   \\/                                            ",
	}
}

func infraASCII() []string {
	return []string{
		" _____        __                                                ",
		"|_   _|      / _|                                               ",
		"  | |  _ __ | |_ _ __ __ _                                      ",
		"  | | | '_ \\|  _| '__/ _` |                                     ",
		" _| |_| | | | | | | | (_| |                                     ",
		"|_____|_| |_|_| |_|  \\__,_|                                     ",
	}
}

func categoryDefaultASCII() []string {
	return []string{
		"                                                                ",
		"                                                                ",
		"                                                                ",
		"                                                                ",
		"                                                                ",
		"                                                                ",
	}
}

func scoreAASCII() []string {
	return []string{
		"          ",
		"    /\\    ",
		"   /  \\   ",
		"  / /\\ \\  ",
		" / ____ \\ ",
		"/_/    \\_\\",
	}
}

func scoreBASCII() []string {
	return []string{
		" ____     ",
		"|  _ \\    ",
		"| |_) |   ",
		"|  _ <    ",
		"| |_) |   ",
		"|____/    ",
	}
}

func scoreCASCII() []string {
	return []string{
		"   ____     ",
		" / ____|   ",
		"| |       ",
		"| |       ",
		"| |____   ",
		" \\_____|  ",
	}
}
