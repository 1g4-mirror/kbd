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
