# SPDX-License-Identifier: Apache-2.0
# Sourced by login bash and by interactive sh via ENV in the appliance image.
case $- in
    *i*) ;;
    *) return ;;
esac

# Keep substitutions in PS1, not interpolated shell source. The OS identity
# and hostname are runtime values, never the saved appliance hostname.
PS1='$(id -un)@$(hostname)(os):\w\$ '
export PS1
printf '%s\n' 'Linux OS shell. OS commands apply immediately and bypass candidate configuration.' \
    'configure opens the configuration CLI; exit ends this shell and returns to its caller.'
