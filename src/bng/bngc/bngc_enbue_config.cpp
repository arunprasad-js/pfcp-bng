/*
* Copyright (c) 2020 Altran
*
* Licensed under the License terms and conditions for use, reproduction,
* and distribution of OPENAIR 5G software (the “License”);
* you may not use this file except in compliance with the License.
* You may obtain a copy of the License at
*
*    https://www.openairinterface.org/?page_id=698
*
* Unless required by applicable law or agreed to in writing, software
* distributed under the License is distributed on an "AS IS" BASIS,
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
* See the License for the specific language governing permissions and
* limitations under the License.
*/
#include "bngc_enbue_config.hpp"
#include "logger.hpp"
#include "rapidjson/filereadstream.h"

#include <cstdio>

#define MAX_READ_BUFFER 65536

using namespace bngc_enbue;
using namespace rapidjson;

Document bngc_enbue::read_bngc_enbue_config_from_file()
{
    return read_bngc_enbue_config_from_file(DEFAULT_BNGC_ENBUE_CONFIG_FILE);
}

Document bngc_enbue::read_bngc_enbue_config_from_file(const char *config_file)
{
    FILE* fp = fopen(config_file, "rb");
    char readBuffer[65536];

    Document d;

    if (fp == NULL) {
        Logger::bngc_enbue_app().error("Could not open config file %s", config_file);
        return d;
    }

    FileReadStream is(fp, readBuffer, sizeof(readBuffer));

    d.ParseStream(is);
    fclose(fp);

    if (d.HasParseError()) {
        Logger::bngc_enbue_app().error("Parsing error in config file %s", config_file);
        exit(1);
    }

    Logger::bngc_enbue_app().debug("Read configurations from %s", config_file);

    return d;
}
