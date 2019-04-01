# ============LICENSE_START=======================================================
# Copyright (c) 2018-2019 AT&T Intellectual Property. All rights reserved.
# ================================================================================
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
# ============LICENSE_END=========================================================
#

"""test of the policy_utils"""

import json
import re

from policyhandler.utils import RegexCoarser, Utils

_LOGGER = Utils.get_logger(__file__)

def check_coarse_regex(test_name, patterns, matching_strings=None, expected_subpatterns=None):
    """generic test"""
    regex_coarser = RegexCoarser(patterns)
    coarse_patterns = regex_coarser.get_coarse_regex_patterns(max_length=20)
    _LOGGER.info("check_coarse_regex %s (%s) for [%s]",
                 test_name, coarse_patterns, json.dumps(regex_coarser.patterns))
    coarse_regexes = [re.compile(coarse_pattern) for coarse_pattern in coarse_patterns]
    coarse_patterns_str = json.dumps(coarse_patterns)
    if matching_strings:
        for test_str in matching_strings:
            _LOGGER.info("  match '%s' to %s (%s)", test_str, test_name, coarse_patterns_str)
            assert bool(list(filter(None, [
                coarse_regex.match(test_str) for coarse_regex in coarse_regexes
            ])))

    if expected_subpatterns:
        for subpattern in expected_subpatterns:
            _LOGGER.info("  subpattern '%s' in %s", subpattern, coarse_patterns_str)
            assert subpattern in coarse_patterns_str

def check_combined_regex(test_name, patterns, matching_strings=None, unmatching_strings=None):
    """generic test"""
    regex_coarser = RegexCoarser(patterns)
    combined_pattern = regex_coarser.get_combined_regex_pattern()
    _LOGGER.info("check_combined_regex %s (%s) for [%s]",
                 test_name, combined_pattern, json.dumps(regex_coarser.patterns))
    coarse_regex = re.compile(combined_pattern)
    if matching_strings:
        for test_str in matching_strings:
            _LOGGER.info("  match '%s' to %s (%s)", test_str, test_name, combined_pattern)
            assert coarse_regex.match(test_str)

    if unmatching_strings:
        for test_str in unmatching_strings:
            _LOGGER.info("  not match '%s' to %s (%s)", test_str, test_name, combined_pattern)
            assert not coarse_regex.match(test_str)

def test_regex_coarser():
    """test variety of regex combinations"""

    test_data = [
        (
            "simple",
            [
                "plain text", "plain pick",
                "aaa (((a|b)|c)|d)",
                "aaa (((a|b)|c)|d zzz",
                "nested (expr[aeiou]ss(ions)?)",
                "nested (expr[aeiou]ss(?:ions|ion)?)",
                "^ (any expr|more|less|some|who cares)",
                " (any expr|more|less|some|who cares)",
                "(any expr|more|less|some|who cares)"
            ],
            [
                'plain text',
                'nested exprussions',
                'nested expross',
                'aaa c',
                'aaa d',
                'who cares',
                ' who cares'
            ],
            None,
            [
                "nested .*",
                "plain .*",
                "aaa .*",
                "(any expr|more|less|some|who cares)",
                "^ (any expr|more|less|some|who cares)",
                " (any expr|more|less|some|who cares)"]
        ),
        (
            "combination",
            [
                "plain text",
                "^with* modifiers?",
                "cha[ra][ra]cter classes",
                "^with (groups)",
                "^with (groups|more groups)",
                r"^with (mod+ifiers\s*|in groups{2,3}\s*)+",
                "sub",
                "substrings",
                "su.*bstrings",
                "char count{1,3}s",
                "nested (expr[aeiou]ss(ions)?)",
                r"escaped (\)) chars",
                r"escaped ([\)\]]) chars",
                r"escaped ([\)\]]){3} chars"
            ],
            [
                'plain text',
                'withhh modifier',
                'character classes',
                'with groups',
                'with more groups',
                'with modddifiers in groupss modifiers in groupsss',
                'sub',
                'substrings',
                'char counttts',
                'nested exprassions',
                'nested express',
                'escaped ) chars',
                'escaped ] chars',
                'escaped ]]] chars'
            ],
            [
                'plain',
                'text',
                'something with modifiers',
                'su',
                'char counttttts',
                'escaped ]] chars'
            ],
            [
                "nested .*",
                "escaped .*",
                "^wit.*",
                "plain text",
                "cha.*",
                "su.*"
            ]
        ),
        (
            "combined",
            [
                'foo+',
                'food',
                'football',
                "ba[rh]",
                "bard"
            ],
            [
                'foo',
                'fooooo',
                'football',
                'food',
                'bar',
                'bah',
                'bard'
            ],
            [
                'fo',
                'bat'
            ],
            [
                "fo.*",
                "ba.*"
            ]
        )
    ]

    for (test_name, patterns,
         matching_strings, unmatching_strings, expected_subpatterns) in test_data:
        check_combined_regex(test_name, patterns, matching_strings, unmatching_strings)
        check_coarse_regex(test_name, patterns, matching_strings, expected_subpatterns)
