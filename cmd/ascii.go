// Copyright © 2022-2024 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

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

func performanceASCII() []string {
	return []string{
		" _____           __                                             ",
		"|  __ \\         / _|                                            ",
		"| |__) |__ _ __| |_ ___  _ __ _ __ ___   __ _ _ __   ___ ___    ",
		"|  ___/ _ \\ '__|  _/ _ \\| '__| '_ ` _ \\ / _` | '_ \\ / __/ _ \\   ",
		"| |  |  __/ |  | || (_) | |  | | | | | | (_| | | | | (_|  __/   ",
		"|_|   \\___|_|  |_| \\___/|_|  |_| |_| |_|\\__,_|_| |_|\\___\\___|   ",
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
