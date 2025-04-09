#!/bin/bash
#
# This script is used to test the validity of the draft.
#
# It replicates the actions performed when a new commit is detected.
#

SCRIPTDIR="$( cd "$(dirname "$0")" ; pwd -P )"
CURRENTSCRIPT="$(basename "$0")"
DRAFTDIR="${SCRIPTDIR}/.."
WORKDIR="${SCRIPTDIR}/work"

usage()
{
	echo "This script emulates the actions taken by the commit"
	echo "actions based on the Docker image i-d-template."
	echo "It allows running the same actions on the author's"
	echo "platform to discover the fitness of the draft before"
	echo "submitting it."
	echo ""
	echo "Usage:"
	echo "     $CURRENTSCRIPT [<option>...]"
	echo ""
	echo "  options:"
	echo ""
	echo "     --process"
	echo "          Attempts to run the regular process. This is"
	echo "          the default action and does not need to be"
	echo "          specified."
	echo ""
	echo "     --interactive"
	echo "          Starts the Docker image in an interactive mode."
	echo "          This allows a developer to run the script manually."
	echo ""
	echo "     --help"
	echo "          Shows help information and quits"
	echo ""
	echo "Examples:"
	echo "     $CURRENTSCRIPT"
	echo ""
}

# Read options
OPT_ACTION=
while [[ $# -gt 0 ]]; do
	case $1 in
		--process)
			OPT_ACTION="process"
			;;
		--interactive)
			OPT_ACTION="interactive"
			;;
		--help)
			usage
			exit 0
			;;
		*)
			echo "*** Unknown option: $1"
			echo ""
			usage
			exit 1;
			;;
	esac
	shift
done

# Parse the action
ENTRYPOINT=
ARGUMENTS=
if [ "process" == "${OPT_ACTION}" ] || [ "" == "${OPT_ACTION}" ]; then
	ARGUMENTS="all"
elif [ "interactive" == "${OPT_ACTION}" ]; then
	ENTRYPOINT="--it --entrypoint /bin/bash"
else
	echo "Error. Unrecognized action: ${OPT_ACTION}"
	exit 1
fi

rm -Rf "${WORKDIR}"
mkdir -p "${WORKDIR}"
mkdir -p "${WORKDIR}/home"
mkdir -p "${WORKDIR}/workflow"
mkdir -p "${WORKDIR}/file_commands"
mkdir -p "${WORKDIR}/workspace"

cp -rp "${DRAFTDIR}"/draft* "${WORKDIR}/workspace"/.
cp -rp "${DRAFTDIR}"/*.asn "${WORKDIR}/workspace"/.
cp -rp "${DRAFTDIR}"/sampledata "${WORKDIR}/workspace"/.

/usr/bin/docker run --name ghcriomartinthomsonidtemplateactionlatest_9b4121 --label 266de7\
 --workdir /github/workspace --rm\
 ${ENTRYPOINT}\
 -e "INPUT_TOKEN" -e "INPUT_MAKE" -e "GITHUB_TOKEN" -e HOME=/github/home -e "GITHUB_JOB"\
 -e "GITHUB_REF" -e "GITHUB_SHA" -e "GITHUB_REPOSITORY" -e "GITHUB_REPOSITORY_OWNER"\
 -e "GITHUB_REPOSITORY_OWNER_ID" -e "GITHUB_RUN_ID" -e "GITHUB_RUN_NUMBER"\
 -e "GITHUB_RETENTION_DAYS" -e "GITHUB_RUN_ATTEMPT" -e "GITHUB_ACTOR_ID" -e "GITHUB_ACTOR"\
 -e "GITHUB_WORKFLOW" -e "GITHUB_HEAD_REF" -e "GITHUB_BASE_REF" -e "GITHUB_EVENT_NAME"\
 -e "GITHUB_SERVER_URL" -e "GITHUB_API_URL" -e "GITHUB_GRAPHQL_URL" -e "GITHUB_REF_NAME"\
 -e "GITHUB_REF_PROTECTED" -e "GITHUB_REF_TYPE" -e "GITHUB_WORKFLOW_REF" -e "GITHUB_WORKFLOW_SHA"\
 -e "GITHUB_REPOSITORY_ID" -e "GITHUB_TRIGGERING_ACTOR" -e "GITHUB_WORKSPACE" -e "GITHUB_ACTION"\
 -e "GITHUB_EVENT_PATH" -e "GITHUB_ACTION_REPOSITORY" -e "GITHUB_ACTION_REF" -e "GITHUB_PATH"\
 -e "GITHUB_ENV" -e "GITHUB_STEP_SUMMARY" -e "GITHUB_STATE" -e "GITHUB_OUTPUT" -e "RUNNER_OS"\
 -e "RUNNER_ARCH" -e "RUNNER_NAME" -e "RUNNER_ENVIRONMENT" -e "RUNNER_TOOL_CACHE" -e "RUNNER_TEMP"\
 -e "RUNNER_WORKSPACE" -e "ACTIONS_RUNTIME_URL" -e "ACTIONS_RUNTIME_TOKEN" -e "ACTIONS_CACHE_URL"\
 -e "ACTIONS_RESULTS_URL" -e GITHUB_ACTIONS=true -e CI=true\
 -v "/var/run/docker.sock":"/var/run/docker.sock"\
 -v "${HOME}":"/github/home"\
 -v "${WORKDIR}/workflow":"/github/workflow"\
 -v "${WORKDIR}/file_commands":"/github/file_commands"\
 -v "${WORKDIR}/workspace":"/github/workspace"\
 ghcr.io/martinthomson/i-d-template-action:latest ${ARGUMENTS}
