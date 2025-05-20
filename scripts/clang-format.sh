#!/usr/bin/env bash
#
# Script to clang-format suricata C code changes
#
# Rewriting branch parts of it is inspired by
# https://www.thetopsites.net/article/53885283.shtml

#set -x

# We verify the minimal clang-format version for better error messaging as older clang-format
# will barf on unknown settings with a generic error.
CLANG_FORMAT_REQUIRED_VERSION=9

EXIT_CODE_ERROR=2
EXIT_CODE_FORMATTING_REQUIRED=1
EXIT_CODE_OK=0

PRINT_DEBUG=0
# Debug output if PRINT_DEBUG is 1
function Debug {
    if [ $PRINT_DEBUG -ne 0 ]; then
        echo "DEBUG: $@"
    fi
}

# ignore text formatting by default
bold=
normal=
italic=
# $TERM is set to dumb when calling scripts in github actions.
if [ -n "$TERM" -a "$TERM" != "dumb" ]; then
    Debug "TERM: '$TERM'"
    # tput, albeit unlikely, might not be installed
    command -v tput >/dev/null 2>&1 # built-in which
    if [ $? -eq 0 ]; then
        Debug "Setting text formatting"
        bold=$(tput bold)
        normal=$(tput sgr0)
        italic=$(echo -e '\E[3m')
    fi
else
    Debug "No text formatting"
fi

EXEC=$(basename $0)
pushd . >/dev/null # we might change dir - save so that we can revert

USAGE=$(cat << EOM
usage: $EXEC --help
       $EXEC help <command>
       $EXEC <command> [<args>]

Format selected changes using clang-format.

Note: This does ONLY format the changed code, not the whole file! It
uses ${italic}git-clang-format${normal} for the actual formatting. If you want to format
whole files, use ${italic}clang-format -i <file>${normal}.

It auto-detects the correct clang-format version and compared to ${italic}git-clang-format${normal}
proper it provides additional functionality such as reformatting of all commits on a branch.

Commands used in various situations:

Formatting branch changes (compared to master or SURICATA_BRANCH env variable):
    branch          Format all changes in branch as additional commit
    rewrite-branch  Format every commit in branch and rewrite history

Formatting single changes:
    cached          Format changes in git staging
    commit          Format changes in most recent commit

Checking if formatting is correct:
    check-branch    Checks if formatting for branch changes is correct

More info an a command:
    help            Display more info for a particular <command>
EOM
)

HELP_BRANCH=$(cat << EOM
${bold}NAME${normal}
        $EXEC branch - Format all changes in branch as additional commit

${bold}SYNOPSIS${normal}
        $EXEC branch [--force]

${bold}DESCRIPTION${normal}
        Format all changes in your branch enabling you to add it as an additional
        formatting commit. It automatically detects all commits on your branch.

        Requires that all changes are committed unless --force is provided.

        You will need to commit the reformatted code.

        This is equivalent to calling:
            $ git clang-format --extensions c,h [--force] first_commit_on_current_branch^

${bold}OPTIONS${normal}
        -f, --force
            Allow changes to unstaged files.

${bold}EXAMPLES${normal}
        On your branch whose changes you want to reformat:

            $ $EXEC branch

${bold}EXIT STATUS${normal}
       $EXEC exits with a status of zero if the changes were successfully
       formatted, or if no formatting change was required. A status of two will
       be returned if any errors were encountered.
EOM
)

HELP_CACHED=$(cat << EOM
${bold}NAME${normal}
        $EXEC cached - Format changes in git staging

${bold}SYNOPSIS${normal}
        $EXEC cached [--force]

${bold}DESCRIPTION${normal}
        Format staged changes using clang-format.

        You will need to commit the reformatted code.

        This is equivalent to calling:
            $ git clang-format --extensions c,h [--force]

${bold}OPTIONS${normal}
        -f, --force
            Allow changes to unstaged files.

${bold}EXAMPLES${normal}
        Format all changes in staging, i.e. in files added with ${italic}git add <file>${normal}.

            $ $EXEC cached

${bold}EXIT STATUS${normal}
       $EXEC exits with a status of zero if the changes were successfully
       formatted, or if no formatting change was required. A status of two will
       be returned if any errors were encountered.
EOM
)

HELP_CHECK_BRANCH=$(cat << EOM
${bold}NAME${normal}
        $EXEC check-branch - Checks if formatting for branch changes is correct

${bold}SYNOPSIS${normal}
        $EXEC check-branch [--show-commits] [--quiet]
        $EXEC check-branch --diff [--show-commits] [--quiet]
        $EXEC check-branch --diffstat [--show-commits] [--quiet]

${bold}DESCRIPTION${normal}
        Check if all branch changes are correctly formatted.

        Note, it does not check every commit's formatting, but rather the
        overall diff between HEAD and master.

        Returns 1 if formatting is off, 0 if it is correct.

${bold}OPTIONS${normal}
        -d, --diff
            Print formatting diff, i.e. diff of each file with correct formatting.
        -s, --diffstat
            Print formatting diffstat output, i.e. files with wrong formatting.
        -c, --show-commits
            Print branch commits.
        -q, --quiet
            Do not print any error if formatting is off, only set exit code.

${bold}EXIT STATUS${normal}
       $EXEC exits with a status of zero if the formatting is correct. A
       status of one will be returned if the formatting is not correct. A status
       of two will be returned if any errors were encountered.
EOM
)

HELP_COMMIT=$(cat << EOM
${bold}NAME${normal}
        $EXEC commit - Format changes in most recent commit

${bold}SYNOPSIS${normal}
        $EXEC commit

${bold}DESCRIPTION${normal}
        Format changes in most recent commit using clang-format.

        You will need to commit the reformatted code.

        This is equivalent to calling:
            $ git clang-format --extensions c,h HEAD^

${bold}EXAMPLES${normal}
        Format all changes in most recent commit:

            $ $EXEC commit

        Note that this modifies the files, but doesn’t commit them – you’ll likely want to run

            $ git commit --amend -a

${bold}EXIT STATUS${normal}
       $EXEC exits with a status of zero if the changes were successfully
       formatted, or if no formatting change was required. A status of two will
       be returned if any errors were encountered.
EOM
)

HELP_REWRITE_BRANCH=$(cat << EOM
${bold}NAME${normal}
        $EXEC rewrite-branch - Format every commit in branch and rewrite history

${bold}SYNOPSIS${normal}
        $EXEC rewrite-branch

${bold}DESCRIPTION${normal}
        Reformat all commits in branch off master one-by-one. This will ${bold}rewrite
        the branch history${normal} using the existing commit metadata!
        It automatically detects all commits on your branch.

        This is handy in case you want to format all of your branch commits
        while keeping the commits.

        This can also be helpful if you have multiple commits in your branch and
        the changed files have been reformatted, i.e. where a git rebase would
        fail in many ways over-and-over again.

        You can achieve the same manually on a separate branch by:
        ${italic}git checkout -n <original_commit>${normal},
        ${italic}git clang-format${normal} and ${italic}git commit${normal} for each original commit in your branch.

${bold}OPTIONS${normal}
        None

${bold}EXAMPLES${normal}
        In your branch that you want to reformat. Commit all your changes prior
        to calling:

            $ $EXEC rewrite-branch

${bold}EXIT STATUS${normal}
       $EXEC exits with a status of zero if the changes were successfully
       formatted, or if no formatting change was required. A status of two will
       be returned if any errors were encountered.
EOM
)

# Error message on stderr
function Error {
    echo "${bold}ERROR${normal}: $@" 1>&2
}

# Exit program (and reset path)
function ExitWith {
    popd >/dev/null # we might have changed dir

    if [ $# -ne 1 ]; then
        # Huh? No exit value provided?
        Error "Internal: ExitWith requires parameter"
        exit $EXIT_CODE_ERROR
    else
        exit $1
    fi
}

# Failure exit with error message
function Die {
    Error $@
    ExitWith $EXIT_CODE_ERROR
}

# Ensure required program exists. Exits with failure if not found.
# Call with
#   RequireProgram ENVVAR_TO_SET program ...
# One can provide multiple alternative programs. Returns first program found in
# provided list.
function RequireProgram {
    if [ $# -lt 2 ]; then
        Die "Internal - RequireProgram: Need env and program parameters"
    fi

    # eat variable to set
    local envvar=$1
    shift

    for program in $@; do
        command -v $program >/dev/null 2>&1 # built-in which
        if [ $? -eq 0 ]; then
            eval "$envvar=$(command -v $program)"
            return
        fi
    done

    if [ $# -eq 1 ]; then
        Die "$1 not found"
    else
        Die "None of $@ found"
    fi
}

# Make sure we are running from the top-level git directory.
# Same approach as for setup-decoder.sh. Good enough.
# We could probably use git rev-parse --show-toplevel to do so, as long as we
# handle the libhtp subfolder correctly.
function SetTopLevelDir {
    if [ -e ./src/suricata.c ]; then
        # Do nothing.
        true
    elif [ -e ./suricata.c -o -e ../src/suricata.c ]; then
        cd ..
    else
        Die "This does not appear to be a suricata source directory."
    fi
}

# print help for given command
function HelpCommand {
    local help_command=$1
    local HELP_COMMAND=$(echo "HELP_$help_command" | sed "s/-/_/g" | tr [:lower:] [:upper:])
    case $help_command in
        branch|cached|check-branch|commit|rewrite-branch)
            echo "${!HELP_COMMAND}";
            ;;

        "")
            echo "$USAGE";
            ;;

        *)
            echo "$USAGE";
            echo "";
            Die "No manual entry for $help_command"
            ;;
    esac
}

# Return first commit of branch (off master or SURICATA_BRANCH env variable).
#
# Use $first_commit^ if you need the commit on master we branched off.
# Do not compare with master directly as it will diff with the latest commit
# on master. If our branch has not been rebased on the latest master, this
# would result in including all new commits on master!
function FirstCommitOfBranch {
    start="${SURICATA_BRANCH:-origin/master}"
    local first_commit=$(git rev-list $start..HEAD | tail -n 1)
    echo $first_commit
}

# Check if branch formatting is correct.
# Compares with master branch as baseline which means it's limited to branches
# other than master.
# Exits with 1 if not, 0 if ok.
function CheckBranch {
    # check parameters
    local quiet=0
    local show_diff=0
    local show_diffstat=0
    local show_commits=0
    local git_clang_format="$GIT_CLANG_FORMAT --diff"
    while [[ $# -gt 0 ]]
    do
    case "$1" in
        -q|--quiet)
            quiet=1
            shift
            ;;

        -d|--diff)
            show_diff=1
            shift
            ;;

        -s|--diffstat)
            show_diffstat=1
            git_clang_format="$GIT_CLANG_FORMAT_DIFFSTAT --diffstat"
            shift
            ;;

        -c|--show-commits)
            show_commits=1
            shift
            ;;

        *)    # unknown option
            echo "$HELP_CHECK_BRANCH";
            echo "";
            Die "Unknown $command option: $1"
            ;;
    esac
    done

    if [ $show_diffstat -eq 1 -a $show_diff -eq 1 ]; then
        echo "$HELP_CHECK_BRANCH";
        echo "";
        Die "Cannot combine $command options --diffstat with --diff"
    fi

    # Find first commit on branch. Use $first_commit^ if you need the
    # commit on master we branched off.
    local first_commit=$(FirstCommitOfBranch)

    # git-clang-format is a python script that does not like SIGPIPE shut down
    # by "| head" prematurely. Use work-around with writing to tmpfile first.
    local format_changes="$git_clang_format --extensions c,h $first_commit^"
    local tmpfile=$(mktemp /tmp/clang-format.check.XXXXXX)
    $format_changes > $tmpfile
    local changes=$(cat $tmpfile | head -1)
    if [ $show_diff -eq 1 -o $show_diffstat -eq 1 ]; then
        cat $tmpfile
        echo ""
    fi
    rm $tmpfile

    # Branch commits can help with trouble shooting. Print after diff/diffstat
    # as output might be tail'd
    if [ $show_commits -eq 1 ]; then
        echo "Commits on branch (new -> old):"
        git log --oneline $first_commit^..HEAD
        echo ""
    else
        if [ $quiet -ne 1 ]; then
            echo "First commit on branch: $first_commit"
        fi
    fi

    # Exit code of git-clang-format is useless as it's 0 no matter if files
    # changed or not. Check actual output. Not ideal, but works.
    if [ "${changes}" != "no modified files to format" -a \
         "${changes}" != "clang-format did not modify any files" ]; then
        if [ $quiet -ne 1 ]; then
            Error "Branch requires formatting"
            Debug "View required changes with clang-format: ${italic}$format_changes${normal}"
            Error "View required changes with: ${italic}$EXEC $command --diff${normal}"
            Error "Use ${italic}./scripts/$EXEC branch${normal} to fix formatting,
            then add formatting changes to a new commit"
            ExitWith $EXIT_CODE_FORMATTING_REQUIRED
        else
            return $EXIT_CODE_FORMATTING_REQUIRED
        fi
    else
        if [ $quiet -ne 1 ]; then
            echo "no modified files to format"
        fi
        return $EXIT_CODE_OK
    fi
}

# Reformat all changes in branch as a separate commit.
function ReformatBranch {
    # check parameters
    local with_unstaged=
    if [ $# -gt 1 ]; then
        echo "$HELP_BRANCH";
        echo "";
        Die "Too many $command options: $1"
    elif [ $# -eq 1 ]; then
        if [ "$1" == "--force" -o  "$1" == "-f" ]; then
            with_unstaged='--force'
        else
            echo "$HELP_BRANCH";
            echo "";
            Die "Unknown $command option: $1"
        fi
    fi

    # Find first commit on branch. Use $first_commit^ if you need the
    # commit on master we branched off.
    local first_commit=$(FirstCommitOfBranch)
    echo "First commit on branch: $first_commit"

    $GIT_CLANG_FORMAT --style file --extensions c,h $with_unstaged $first_commit^
    if [ $? -ne 0 ]; then
        Die "Cannot reformat branch. git clang-format failed"
    fi
}

# Reformat changes in commit
function ReformatCommit {
    # check parameters
    local commit=HEAD^ # only most recent for now
    if [ $# -gt 0 ]; then
        echo "$HELP_MOST_RECENT";
        echo "";
        Die "Too many $command options: $1"
    fi

    $GIT_CLANG_FORMAT --style file --extensions c,h $commit
    if [ $? -ne 0 ]; then
        Die "Cannot reformat most recent commit. git clang-format failed"
    fi
}

# Reformat currently staged changes
function ReformatCached {
    # check parameters
    local with_unstaged=
    if [ $# -gt 1 ]; then
        echo "$HELP_CACHED";
        echo "";
        Die "Too many $command options: $1"
    elif [ $# -eq 1 ]; then
        if [ "$1" == "--force" -o  "$1" == "-f" ]; then
            with_unstaged='--force'
        else
            echo "$HELP_CACHED";
            echo "";
            Die "Unknown $command option: $1"
        fi
    fi

    $GIT_CLANG_FORMAT --style file --extensions c,h $with_unstaged
    if [ $? -ne 0 ]; then
        Die "Cannot reformat staging. git clang-format failed"
    fi
}

# Reformat all commits of a branch (compared with master) and rewrites
# the history with the formatted commits one-by-one.
# This is helpful for quickly reformatting branches with multiple commits,
# or where the master version of a file has been reformatted.
#
# You can achieve the same manually by git checkout -n <commit>, git clang-format
# for each commit in your branch.
function ReformatCommitsOnBranch {
    # Do not allow rewriting of master.
    # CheckBranch below will also tell us there are no changes compared with
    # master, but let's make this foolproof and explicit here.
    local current_branch=$(git rev-parse --abbrev-ref HEAD)
    if [ "$current_branch" == "master" ]; then
        Die "Must not rewrite master branch history."
    fi

    CheckBranch "--quiet"
    if [ $? -eq 0 ]; then
        echo "no modified files to format"
    else
        # Only rewrite if there are changes
        # Squelch warning. Our usage of git filter-branch is limited and should be ok.
        # Should investigate using git-filter-repo in the future instead.
        export FILTER_BRANCH_SQUELCH_WARNING=1

        # Find first commit on branch. Use $first_commit^ if you need the
        # commit on master we branched off.
        local first_commit=$(FirstCommitOfBranch)
        echo "First commit on branch: $first_commit"
        # Use --force in case it's run a second time on the same branch
        git filter-branch --force --tree-filter "$GIT_CLANG_FORMAT $first_commit^" -- $first_commit..HEAD
        if [ $? -ne 0 ]; then
            Die "Cannot rewrite branch. git filter-branch failed"
        fi
    fi
}

if [ $# -eq 0 ]; then
    echo "$USAGE";
    Die "Missing arguments. Call with one argument"
fi

SetTopLevelDir

RequireProgram GIT git
# ubuntu uses clang-format-{version} name for newer versions. fedora not.
RequireProgram GIT_CLANG_FORMAT git-clang-format-14 git-clang-format-11 git-clang-format-10 git-clang-format-9 git-clang-format
GIT_CLANG_FORMAT_BINARY=clang-format
if [[ $GIT_CLANG_FORMAT =~ .*git-clang-format-14$ ]]; then
    # default binary is clang-format, specify the correct version.
    # Alternative: git config clangformat.binary "clang-format-14"
    GIT_CLANG_FORMAT_BINARY="clang-format-14"
elif [[ $GIT_CLANG_FORMAT =~ .*git-clang-format-11$ ]]; then
    # default binary is clang-format, specify the correct version.
    # Alternative: git config clangformat.binary "clang-format-11"
    GIT_CLANG_FORMAT_BINARY="clang-format-11"
elif [[ $GIT_CLANG_FORMAT =~ .*git-clang-format-10$ ]]; then
    # default binary is clang-format, specify the correct version.
    # Alternative: git config clangformat.binary "clang-format-10"
    GIT_CLANG_FORMAT_BINARY="clang-format-10"
elif [[ $GIT_CLANG_FORMAT =~ .*git-clang-format-9$ ]]; then
    # default binary is clang-format, specify the correct version.
    # Alternative: git config clangformat.binary "clang-format-9"
    GIT_CLANG_FORMAT_BINARY="clang-format-9"
elif [[ $GIT_CLANG_FORMAT =~ .*git-clang-format$ ]]; then
    Debug "Using regular clang-format"
else
    Debug "Internal: unhandled clang-format version"
fi

# enforce minimal clang-format version as required by .clang-format
clang_format_version=$($GIT_CLANG_FORMAT_BINARY --version | sed 's/.*clang-format version \([0-9]*\.[0-9]*\.[0-9]*\).*/\1/')
Debug "Found clang-format version: $clang_format_version"
clang_format_version_major=$(echo $clang_format_version | sed 's/\([0-9]*\)\.\([0-9]*\)\.\([0-9]*\).*/\1/')
Debug "clang-format version major: $clang_format_version_major"
if [ $((clang_format_version_major + 0)) -lt $((CLANG_FORMAT_REQUIRED_VERSION + 0)) ]; then
    Die "Require clang version $CLANG_FORMAT_REQUIRED_VERSION, found $clang_format_version_major ($clang_format_version)."
fi

# overwrite git-clang-version for --diffstat as upstream does not have that yet
RequireProgram GIT_CLANG_FORMAT_DIFFSTAT scripts/git-clang-format-custom
if [ "$GIT_CLANG_FORMAT_BINARY" != "clang-format" ]; then
    GIT_CLANG_FORMAT="$GIT_CLANG_FORMAT --binary $GIT_CLANG_FORMAT_BINARY"
    GIT_CLANG_FORMAT_DIFFSTAT="$GIT_CLANG_FORMAT_DIFFSTAT --binary $GIT_CLANG_FORMAT_BINARY"
fi
Debug "Using $GIT_CLANG_FORMAT"
Debug "Using $GIT_CLANG_FORMAT_DIFFSTAT"

command_rc=0
command=$1
case $command in
    branch)
        shift;
        ReformatBranch "$@";
        ;;

    check-branch)
        shift;
        CheckBranch "$@";
        command_rc=$?;
        ;;

    cached)
        shift;
        ReformatCached "$@";
        ;;

    commit)
        shift;
        ReformatCommit "$@";
        ;;

    rewrite-branch)
        ReformatCommitsOnBranch
        ;;

    help)
        shift;
        HelpCommand $1;
        ;;

    -h|--help)
        echo "$USAGE";
        ;;

    *)
        Die "$EXEC: '$command' is not a command. See '$EXEC --help'"
        ;;
esac

ExitWith $command_rc
