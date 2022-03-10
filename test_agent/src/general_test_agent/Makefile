# Makefile to help build RS911x SQA test agent 
UC ?=uc
RM_DIR ?=rm -rf
CP_DIR ?=cp -r
PYTHON3 ?=python3
GECKO_SDK ?= ~/mini_gecko_sdk

.PHONY: binary uc_generate release generate_sapi_uc

all: binary

binary: uc_generate
	$(MAKE) -C build/ -f sqa_test_agent.Makefile -j
	
uc_generate: generate_sapi_uc sqa_test_agent.slcp
	$(RM_DIR) build
	$(UC) generate -s $(GECKO_SDK) --copy-sdk-sources -p sqa_test_agent.slcp -d build -o makefile

generate_sapi_uc:
	$(RM_DIR) $(GECKO_SDK)/platform/radio/wifi/rs9116/*
	$(CP_DIR) ../../component $(GECKO_SDK)/platform/radio/wifi/rs9116/
	$(CP_DIR) ../../sapi $(GECKO_SDK)/platform/radio/wifi/rs9116/
	$(CP_DIR) ../../platforms/efx32 $(GECKO_SDK)/platform/radio/wifi/rs9116/
	$(CP_DIR) ../../third_party $(GECKO_SDK)/platform/radio/wifi/rs9116/

# Below is a reference on how to install UC
install_uc:
	cd ~ && git clone ssh://git@stash.silabs.com/simplicity_studio/uc_cli.git
	cd uc_cli && $(PYTHON3) uc