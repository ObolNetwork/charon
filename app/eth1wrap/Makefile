.PHONY: generate-bindings

generate-bindings:
	mkdir -p build
	mkdir -p generated
	solc --abi interfaces/IERC1271.sol -o build --overwrite
	abigen --abi=build/IERC1271.abi --pkg=erc1271 --out=generated/erc1271.go