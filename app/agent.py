# ruff: noqa
# Copyright 2026 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import datetime
import json
from pathlib import Path
from zoneinfo import ZoneInfo

from a2ui.basic_catalog.provider import BasicCatalog
from a2ui.schema.manager import A2uiSchemaManager
from google.adk.agents import Agent
from google.adk.apps import App
from google.adk.code_executors import AgentEngineSandboxCodeExecutor
from google.adk.models import Gemini
from google.adk.tools.load_memory_tool import load_memory_tool
from google.adk.tools.preload_memory_tool import preload_memory_tool
from google.genai import types

from app.a2ui_utils import a2ui_callback
from app.tools import (
    analyze_live_call_transcript,
    analyze_url_security,
    generate_threat_warning_infographic,
    generate_threat_warning_video,
    geocode_address,
    log_scam_incident,
    lookup_ip_threat_intelligence,
    lookup_scam_incidents,
    notify_trusted_guardian,
    search_nearby_places,
)

# Read agent engine resource name and memory service URI from deployment_metadata.json if available
deployment_metadata_file = (
    Path(__file__).parent.parent / "deployment_metadata.json"
)
agent_engine_resource_name = None
memory_service_uri = None

if deployment_metadata_file.exists():
    try:
        with open(deployment_metadata_file, "r") as f:
            metadata = json.load(f)
            agent_engine_resource_name = metadata.get(
                "remote_agent_runtime_id"
            )
            memory_service_uri = metadata.get("memory_service_uri")
    except Exception:
        agent_engine_resource_name = None
        memory_service_uri = None

code_executor = AgentEngineSandboxCodeExecutor(
    agent_engine_resource_name=agent_engine_resource_name
)

# Build system prompt with A2UI schema manager v0.8 and Basic Catalog
a2ui_schema_manager = A2uiSchemaManager(
    version="0.8",
    catalogs=[BasicCatalog.get_config("0.8")],
)

a2ui_instruction = a2ui_schema_manager.generate_system_prompt(
    role_description=(
        "You are ScamGuard AI, an expert cybersecurity and anti-fraud assistant. "
        "Your mission is to protect users from phishing, financial, crypto, phone, and imposter scams."
    ),
    workflow_description=(
        "Analyze the user's request, run appropriate threat tools, and return structured A2UI cards when appropriate. "
        "Use `lookup_scam_incidents` to search existing threat reports. "
        "Use `log_scam_incident` to record new verified scam threats. "
        "Use `analyze_url_security` to inspect links and domain entropy. "
        "Use `analyze_live_call_transcript` to evaluate call transcripts for coercion triggers. "
        "Use `notify_trusted_guardian` to send emergency security alerts to family caregivers when high-risk live call coercion is detected. "
        "Use `lookup_ip_threat_intelligence` for network, ISP, and proxy/VPN risk data. "
        "Use `geocode_address` to convert addresses into coordinates. "
        "Use `search_nearby_places` to find nearby police stations or bank branches. "
        "Use `generate_threat_warning_infographic` to generate visual threat warning graphics. "
        "Use `generate_threat_warning_video` to generate animated short warning video clips using gemini-omni-flash-preview. "
        "Use `load_memory` to recall past conversation history and security preferences."
    ),
    ui_description=(
        "Keep every surface tiny and flat: ONE Card > ONE Column > a few Text rows. "
        "Never nest a Card inside a Card. "
        "Use ONLY these components: Card, Column, Row, Text, and Image. Do not use "
        "Table or Heading (unsupported), or Buttons, actions, or forms (they do "
        "nothing in adk web). "
        "You may include one Image component, but only when you have a public https "
        "URL for the image (for example the URL an image tool returns after uploading "
        "to a public bucket). Set the Image url to that exact https link, for example "
        '{"Image": {"url": {"literalString": "https://..."}}}. Never point an '
        "Image at a bare filename, an artifact name, or a non-http(s) path. If you do "
        "not have a public URL, add a short Text line noting the image instead. "
        "No markdown in text; use the usageHint property ('h1', 'h2', 'body') for "
        "headings and emphasis. "
        "Output ONLY the raw A2UI JSON array — no prose, and never wrap it in "
        "<a2a_datapart_json> tags or 'kind'/'data'/'metadata' objects."
    ),
    include_schema=True,
    include_examples=True,
)


root_agent = Agent(
    name="root_agent",
    model=Gemini(
        model="gemini-2.5-flash",
        retry_options=types.HttpRetryOptions(attempts=3),
    ),
    code_executor=code_executor,
    instruction=a2ui_instruction,
    after_model_callback=a2ui_callback,
    tools=[
        lookup_scam_incidents,
        log_scam_incident,
        analyze_url_security,
        analyze_live_call_transcript,
        notify_trusted_guardian,
        lookup_ip_threat_intelligence,
        geocode_address,
        search_nearby_places,
        generate_threat_warning_infographic,
        generate_threat_warning_video,
        load_memory_tool,
        preload_memory_tool,
    ],
)

app = App(
    root_agent=root_agent,
    name="app",
)

