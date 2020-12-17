# Getting support for fio

## General questions

Please use the fio mailing list for asking general fio questions (e.g. "How do
I do X?", "Why does Y happen?"). See the Mailing list section of the
[README][readme] for details).

## Reporting bugs

As mentioned in [REPORTING-BUGS][reportingbugs], fio bugs and enhancements can
be reported to the fio mailing list or fio's GitHub issues tracker.

When reporting bugs please include ALL of the following:
- Description of the issue
- fio version number tested. If your fio isn't among the recent releases (see
  the [fio releases page][releases]) please build a new one from source (see
  the Source and Building sections of the [README][readme] for how to do this)
  and reproduce the issue with the fresh build before filing an issue.
- Reproduction steps and minimal job file/command line parameters.

When requesting an enhancement only the description is needed.

### GitHub issues specific information

[Formatting terminal output with markdown][quotingcode] will help people who
are reading your report. However, if the output is large (e.g. over 15 lines
long) please consider including it as a text attachment. Avoid attaching
pictures of screenshots as these are not searchable/selectable.

<!-- Definitions -->

[readme]: ../README
[reportingbugs]: ../REPORTING-BUGS
[releases]: ../../../releases
[quotingcode]: https://docs.github.com/en/free-pro-team@latest/github/writing-on-github/basic-writing-and-formatting-syntax#quoting-code
