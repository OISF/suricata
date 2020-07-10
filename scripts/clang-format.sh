#!/bin/bash
# Copyright (C) 2020 Open Information Security Foundation
#
# You can copy, redistribute or modify this Program under the terms of
# the GNU General Public License version 2 as published by the Free
# Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# version 2 along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
# 02110-1301, USA.

# Script to clang-format suricata C code changes
#
# Rewriting branch parts of it is inspired by
# https://www.thetopsites.net/article/53885283.shtml

#set -e
#set -x

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
# $TERM is not set for github actions and is set to dumb when calling things
# from github actions.
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


Commands used in various situations:

Formatting branch changes (compared to master):
    branch          Format all changes in branch as additional commit
    rewrite-branch  Format every commit in branch and rewrite history

Formatting single changes:
    cached          Format changes in git staging

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
        $EXEC branch [<options>]
        $EXEC b [<options>]

${bold}DESCRIPTION${normal}
        Format all changes in your branch enabling you to add it as an additional
        formatting commit.

        Requires that all changes are committed unless --force is provided.

        You will need to commit the reformatted code.

${bold}OPTIONS${normal}
        -f, --force
            Allow changes to unstaged files.

${bold}EXAMPLES${normal}
        On your branch whose changes you want to reformat:

            $ $EXEC branch
EOM
)

HELP_CACHED=$(cat << EOM
${bold}NAME${normal}
        $EXEC cached - Format changes in git staging

${bold}SYNOPSIS${normal}
        $EXEC cached [<options>]
        $EXEC d [<options>]

${bold}DESCRIPTION${normal}
        Format staged changes using clang-format.

        You will need to commit the reformatted code.

${bold}OPTIONS${normal}
        -f, --force
            Allow changes to unstaged files.

${bold}EXAMPLES${normal}
        Format all changes in staging, i.e. in files added with ${italic}git add <file>${normal}.

            $ $EXEC cached
EOM
)

HELP_CHECK_BRANCH=$(cat << EOM
${bold}NAME${normal}
        $EXEC check-branch - Checks if formatting for branch changes is correct

${bold}SYNOPSIS${normal}
        $EXEC check-branch [<options>]
        $EXEC c [<options>]

${bold}DESCRIPTION${normal}
        Check if all branch changes are correctly formatted.

        Note, it does not check every commit's formatting, but rather the
        overall diff between HEAD and master.

        Returns 1 if formatting is off, 0 if it is correct.

${bold}OPTIONS${normal}
        -d, --diff
            Print formatting diff output. If not set, do not print any diff output.
        -m, --make
            Print commands as make calls. If not set, print as clang-format.sh calls.
        -q, --quiet
            Do not print any error if formatting is off, only set exit code.
EOM
)

HELP_REWRITE_BRANCH=$(cat << EOM
${bold}NAME${normal}
        $EXEC rewrite-branch - Format every commit in branch and rewrite history

${bold}SYNOPSIS${normal}
        $EXEC rewrite-branch
        $EXEC r

${bold}DESCRIPTION${normal}
        Reformat all commits in branch off master one-by-one. This will ${bold}rewrite
        the branch history${normal} using the existing commit metadata!

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
EOM
)

# Error message on stderr
function Error {
    echo "${bold}ERROR${normal}: $@" 1>&2
}

# Failure exit with error message
function Die {
    popd >/dev/null # we might have changed dir
    Error $@
    exit 1
}

# Ensure required program exists. One can provide multiple alternative programs.
# Exits with failure if not.
# Returns first program found in provided list.
function RequireProgram {
    if [ $# -eq 0 ]; then
        Die "Internal - RequireProgram: No program provided"
    fi

    for program in $@; do
        command -v $program >/dev/null 2>&1 # built-in which
        if [ $? -eq 0 ]; then
            echo "$(command -v $program)"
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
        branch|cached|check-branch|rewrite-branch)
            echo "${!HELP_COMMAND}";
            ;;

        "")
            echo "$USAGE";
            ;;

        *)
            echo "$USAGE";
            echo "";
            Die "Unknown $command arguments: $help_command"
            ;;
    esac
}

# Return first commit of branch (off master).
#
# Use $first_commit^ if you need the commit on master we branched off.
# Do not compare with master directly as it will diff with the latest commit
# on master. If our branch has not been rebased on the latest master, this
# would result in including all new commits on master!
function FirstCommitOfBranch {
    local first_commit=$(git rev-list origin/master..HEAD | tail -n 1)
    echo $first_commit
}

# Check if branch formatting is correct.
# Compares with master branch as baseline which means it's limited to branches
# other than master.
# Exits with 1 if not, 0 if ok.
function CheckBranch {
    # check parameters
    local quiet=0
    local from_make=0
    local show_diff=0
    local show_diffstat=0
    local git_clang_format_diff="$GIT_CLANG_FORMAT --diff"
    while [[ $# -gt 0 ]]
    do
    case "$1" in
        -q|--quiet)
            quiet=1
            shift
            ;;

        -m|--make)
            from_make=1
            shift
            ;;

        -d|--diff)
            show_diff=1
            shift
            ;;

        -s|--diffstat)
            show_diffstat=1
            git_clang_format_diff="$GIT_CLANG_FORMAT_DIFFSTAT --diffstat"
            shift
            ;;

        *)    # unknown option
            echo "$USAGE";
            echo "";
            Die "Unknown $command argument: $1"
            ;;
    esac
    done

    if [ $show_diffstat -eq 1 -a $show_diff -eq 1 ]; then
        echo "$USAGE";
        echo "";
        Die "$command: Cannot combine --diffstat with --diff"
    fi

    # Find first commit on branch. Use $first_commit^ if you need the
    # commit on master we branched off.
    local first_commit=$(FirstCommitOfBranch)

    # git-clang-format is a python script that does not like SIGPIPE shut down
    # by "| head" prematurely. Use work-around with writing to tmpfile first.
    local format_changes="$git_clang_format_diff --extensions c,h $first_commit^"
    local tmpfile=$(mktemp /tmp/clang-format.check.XXXXXX)
    $format_changes > $tmpfile
    local changes=$(cat $tmpfile | head -1)

    # Exit code of git-clang-format is useless as it's 0 no matter if files
    # changed or not. Check actual output. Not ideal, but works.
    if [ "${changes}" != "no modified files to format" -a \
         "${changes}" != "clang-format did not modify any files" ]; then
        if [ $show_diff -eq 1 -o $show_diffstat -eq 1 ]; then
            cat $tmpfile
            echo ""
        fi
        rm $tmpfile

        if [ $quiet -ne 1 ]; then
            echo "First commit on branch: $first_commit"
            Error "Branch requires formatting"
            Debug "View required changes with: ${italic}$format_changes${normal}"
            if [ $from_make -eq 1 ]; then
                Error "View required changes with: ${italic}make diff-style-branch${normal}"
                Die "Use ${italic}make style-rewrite-branch${normal} or ${italic}make style-branch${normal} to fix formatting"
            else
                Error "View required changes with: ${italic}$EXEC $command --diff${normal}"
                Die "Use ${italic}$EXEC rewrite-branch${normal} or ${italic}$EXEC branch${normal} to fix formatting"
            fi
        else
            return 1
        fi
    else
        rm $tmpfile

        if [ $quiet -ne 1 ]; then
            echo "First commit on branch: $first_commit"
            echo "no modified files to format"
        fi
        return 0
    fi
}

# Reformat all changes in branch as a separate commit.
function ReformatBranch {
    # check parameters
    local with_unstaged=
    if [ $# -gt 1 ]; then
        echo "$USAGE";
        echo "";
        Die "Too many $command arguments: $@"
    elif [ $# -eq 1 ]; then
        if [ "$1" == "--force" -o  "$1" == "-f" ]; then
            with_unstaged='--force'
        else
            echo "$USAGE";
            echo "";
            Die "Unknown $command argument: $1"
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

# Reformat currently staged changes
function ReformatCached {
    # check parameters
    local with_unstaged=
    if [ $# -gt 1 ]; then
        echo "$USAGE";
        echo "";
        Die "Too many $command arguments: $@"
    elif [ $# -eq 1 ]; then
        if [ "$1" == "--force" -o  "$1" == "-f" ]; then
            with_unstaged='--force'
        else
            echo "$USAGE";
            echo "";
            Die "Unknown $command argument: $1"
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
function ReformatCommits {
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

GIT=$(RequireProgram git)
# ubuntu uses clang-format-9 name. fedora not.
GIT_CLANG_FORMAT=$(RequireProgram git-clang-format-9 git-clang-format)
GIT_CLANG_FORMAT_BINARY=
if [[ $GIT_CLANG_FORMAT =~ .*git-clang-format-9$ ]]; then
    # default binary is clang-format, specify the correct version.
    # Alternative: git config --global clangformat.binary "clang-format-9"
    GIT_CLANG_FORMAT_BINARY="--binary clang-format-9"
elif [[ $GIT_CLANG_FORMAT =~ .*git-clang-format$ ]]; then
    Debug "Using regular clang-format"
else
    Debug "Internal: unhandled clang-format version"
fi

# overwite git-clang-version for --diffstat as upstream does not have that yet
GIT_CLANG_FORMAT_DIFFSTAT=$(RequireProgram scripts/git-clang-format-custom)
GIT_CLANG_FORMAT="$GIT_CLANG_FORMAT $GIT_CLANG_FORMAT_BINARY"
GIT_CLANG_FORMAT_DIFFSTAT="$GIT_CLANG_FORMAT_DIFFSTAT $GIT_CLANG_FORMAT_BINARY"
Debug "Using $GIT_CLANG_FORMAT"
Debug "Using $GIT_CLANG_FORMAT_DIFFSTAT"

command_rc=0
command=$1
case $command in
    b|branch)
        shift;
        ReformatBranch "$@";
        ;;
  
    c|check-branch)
        shift;
        CheckBranch "$@";
        command_rc=$?;
        ;;

    d|cached)
        shift;
        ReformatCached "$@";
        ;;

    r|rewrite-branch)
        ReformatCommits
        ;;

    help)
        shift;
        HelpCommand $1;
        ;;

    -h|--help)
        echo "$USAGE";
        ;;

    *)
        echo "$USAGE";
        echo "";
        Die "Unknown arguments: $command"
        ;;
esac

popd >/dev/null # we might have changed dir
exit $command_rc
