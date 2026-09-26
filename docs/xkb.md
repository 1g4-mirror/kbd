# XKB layout conversion for the Linux console

kbd manages the Linux virtual console. It does not configure keyboard
layouts for X11 or Wayland sessions.

When kbd is built with XKB support, `loadkeys` can use XKB layout
descriptions as input and convert them into Linux kernel console keymaps.
This is useful when an XKB layout exists but no equivalent kbd keymap is
available under the keymap data directory.

## Build requirements

XKB conversion is available when kbd is built with libxkbcommon support.
The configure option is:

```sh
./configure --enable-xkb
```

The default configure mode is `auto`: XKB support is enabled when
libxkbcommon is found and disabled otherwise.

## Basic usage

Load an XKB layout into the Linux virtual console:

```sh
loadkeys --xkb-layout us
```

Use a model, layout variant, or XKB options:

```sh
loadkeys --xkb-model pc105 --xkb-layout us --xkb-variant intl
loadkeys --xkb-layout us,ru --xkb-options grp:caps_toggle
```

Check that a layout can be converted without loading it:

```sh
loadkeys --parse --xkb-layout de
```

Write the converted keymap in kbd text format:

```sh
loadkeys --tkeymap --xkb-layout us --xkb-variant intl > us-intl.map
```

Select the locale used to look up XKB compose data:

```sh
loadkeys --xkb-layout us --xkb-variant intl --xkb-locale en_US.UTF-8
```

If `--xkb-locale` is not specified, `loadkeys` tries `LC_ALL`,
`LC_CTYPE`, `LANG`, and then `C`.

## What gets converted

The converter resolves the requested XKB model, layout, variant and
options through the standard `evdev` XKB rules. It then converts the
resulting symbols, modifier behavior, compose entries, keypad mappings
and virtual console switching mappings into the kernel keymap format
where the Linux console can represent them.

Not every XKB semantic has a direct Linux console equivalent. XKB is a
richer input model than the kernel console keymap interface, so conversion
necessarily preserves the behavior that can be expressed through the
Linux virtual console.

## Temporary group switching

`grp:switch` uses RightAlt to select the next group while the key is held.
For example:

```sh
loadkeys --xkb-layout us,ru --xkb-options grp:switch
```

The converter maps `Mode_switch` (also named `ISO_Group_Shift`) to the
console action `CtrlR`. This uses the independent `KG_CTRLR` bit; ordinary
left and right Control keys still use `Control` (`KG_CTRL`). The existing
`KG_SHIFTL` and `KG_SHIFTR` bits continue to select the locked group.

When a keymap contains `Mode_switch`, the converter adds tables 128–191
alongside tables 0–63. With `KG_CTRLR` set, these tables select the next
XKB group, wrapping at the total number of groups. Per-key layout fallback
is still resolved by libxkbcommon. Releasing the switch clears `KG_CTRLR`
and returns to the group selected by the locked group bits.

The console looks up key releases in the current table, without remembering
the action used at key press. In the extra tables, every key that can produce
`Mode_switch` therefore keeps the `CtrlR` action under all modifiers. This
allows RightAlt to be released after pressing Shift or changing the locked
group. In the ordinary tables, original assignments are preserved, including
`Shift+RightAlt = Compose` where XKB defines it. If the locked group changes
while RightAlt is held, releasing RightAlt returns to that newly selected
group.

This represents a single held group switch. Multiple `Mode_switch` keys
share the same bit: holding several does not advance several groups, and
while one is held, the others also act as group switches rather than their
alternate bindings. Arbitrary XKB actions attached to `Mode_switch` are not
interpreted; conversion assumes the usual `SetGroup(group=+1)` behavior.

The existing limitations of other group actions and of releasing an ordinary
modifier after its binding changes between groups still apply.

## Scope and limitations

- XKB conversion affects the Linux virtual console keymap only.
- It does not change X11, Wayland, desktop environment, or terminal
  emulator keyboard settings.
- Loading a console keymap changes the kernel keyboard translation table
  shared by all Linux virtual consoles.
- Compose data may depend on the selected locale and installed XKB data.
- A converted keymap should be tested with `--parse` or `--tkeymap`
  before it is loaded on systems where console input is critical.

See also [`loadkeys(1)`](https://kbd-project.org/manpages/man1/loadkeys.1.html)
and [`keymaps(5)`](https://kbd-project.org/manpages/man5/keymaps.5.html).

See [XKB compose conversion](xkb-compose.md) for compose filtering,
priorities, conflict resolution, and kernel table limits.
