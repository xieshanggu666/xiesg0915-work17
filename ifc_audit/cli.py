"""命令行入口。

用法::

    python -m ifc_audit.cli audit model.ifc -o output/
    python -m ifc_audit.cli batch ifc目录/ --project XX项目 -o output/batch/
    python -m ifc_audit.cli trend --project XX项目
    python -m ifc_audit.cli gui              # 图形界面
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys

from .pipeline import audit_ifc, audit_ifc_with_config
from . import report
from .report import KIND_CN, SEV_CN
from .thresholds import (
    PROFILES, PROFILE_CN, parse_set_items, ThresholdConfigError,
    write_config_template,
)
from .gate import (
    GATE_PROFILES, GATE_PROFILE_CN, parse_gate_set_items, GateConfigError,
    write_gate_config_template,
)
from .batch import (
    run_batch_with_config, run_batch_with_rule_pack, attach_trend,
    save_batch_snapshot, load_project_history,
)
from . import batch_report
from .rule_packs import (
    RulePackLibrary, RulePackError, CHECKS, CHECK_CN,
    STAGES, STAGE_CN, DEFAULT_RULE_LIBRARY, new_draft, write_draft_template,
    resolve_rule_pack, materialize,
)


# ------------------------------------------------------- 规则库子命令 ----

def _rule_lib(args) -> RulePackLibrary:
    return RulePackLibrary(getattr(args, "rule_lib", None)
                           or DEFAULT_RULE_LIBRARY)


def _add_rule_pack_args(parser, auto_flag: bool = False) -> None:
    """audit / batch 共用的规则包参数。"""
    parser.add_argument("--rule-lib", default=DEFAULT_RULE_LIBRARY,
                        help=f"企业规则库目录（默认 {DEFAULT_RULE_LIBRARY}）")
    parser.add_argument("--rule-pack", default=None, metavar="名称[@版本]|快照.json",
                        help="显式指定企业规则包：库内名称（最新版）、名称@版本，"
                             "或已发布快照 JSON 文件路径")
    if auto_flag:
        parser.add_argument("--use-rule-pack", dest="use_rule_pack",
                            action="store_true",
                            help="不指定 --rule-pack 时，按项目/阶段从规则库"
                                 "自动选择适用的已发布规则包")
    parser.add_argument("--stage", choices=STAGES, default="",
                        help="项目阶段（自动选择规则包用）："
                             + " / ".join(f"{k}={v}" for k, v in STAGE_CN.items()))


def _print_pack_row(item: dict) -> None:
    scope_p = "、".join(item["projects"]) if item["projects"] else "全部项目"
    scope_s = "、".join(STAGE_CN.get(s, s) for s in item["stages"]) \
        if item["stages"] else "全部阶段"
    flags = []
    if item["deprecated"]:
        flags.append("最新版已废止")
    if item["has_draft"]:
        flags.append("有未发布草稿")
    print(f"  {item['name']:<20} v{item['latest'] or '-':<10} "
          f"{item['n_versions']} 个版本  [{scope_p} / {scope_s}]"
          f"{'  （' + '，'.join(flags) + '）' if flags else ''}")
    if item["description"]:
        print(f"    └ {item['description']}")


def _cmd_rulepack_list(args) -> int:
    lib = _rule_lib(args)
    items = lib.list_packs()
    if not items:
        print(f"规则库（{lib.root}）中还没有规则包。"
              "可用 `rulepack init` 创建第一份草稿。")
        return 0
    print(f"规则库：{lib.root}（共 {len(items)} 个规则包）")
    for item in items:
        _print_pack_row(item)
    return 0


def _cmd_rulepack_init(args) -> int:
    lib = _rule_lib(args)
    lib.init()
    content = new_draft(
        args.name, description=args.description or "",
        projects=args.project or [], stages=args.stage or [],
        threshold_profile=args.profile,
        gate_profile=("loose" if args.profile == "loose" else "default"))
    try:
        path = lib.save_draft(content)
    except RulePackError as exc:
        print(f"规则包错误：{exc}", file=sys.stderr)
        return 2
    print(f"规则包草稿已创建：{path}")
    print(f"核查项全开；阈值预设 {args.profile}。编辑草稿后发布：")
    print(f"  python -m ifc_audit.cli rulepack publish {args.name} "
          f"1.0.0 --rule-lib {lib.root}")
    return 0


def _cmd_rulepack_show(args) -> int:
    lib = _rule_lib(args)
    try:
        pack = resolve_rule_pack(args.spec, lib)
    except RulePackError as exc:
        print(f"规则包错误：{exc}", file=sys.stderr)
        return 2
    print(f"规则包        : {pack.id}")
    print(f"说明          : {pack.description or '-'}")
    print(f"适用项目      : {'、'.join(pack.projects) if pack.projects else '全部项目'}")
    print(f"适用阶段      : "
          f"{'、'.join(STAGE_CN.get(s, s) for s in pack.stages) if pack.stages else '全部阶段'}")
    print(f"发布时间 / 人 : {pack.published_at} / {pack.published_by or '-'}")
    print(f"内容指纹      : {pack.content_hash}")
    if pack.deprecated:
        print("状态          : 已废止（不参与自动选择）")
    print("核查项：")
    for c in CHECKS:
        on = pack.checks.get(c, True)
        print(f"  [{'x' if on else ' '}] {CHECK_CN[c]}（{c}）")
    print(f"判定阈值      : 预设 {pack.threshold_profile}"
          + (f"，覆盖 {len(pack.thresholds)} 项" if pack.thresholds else ""))
    for k, v in sorted(pack.thresholds.items()):
        print(f"    {k} = {v}")
    print(f"放行门禁      : 预设 {pack.gate_profile}"
          + (f"，覆盖 {len(pack.gate_rules)} 项" if pack.gate_rules else ""))
    for k, v in sorted(pack.gate_rules.items()):
        print(f"    {k} = {v}")
    return 0


def _cmd_rulepack_publish(args) -> int:
    lib = _rule_lib(args)
    try:
        pack = lib.publish(args.source, args.version,
                           published_by=args.by or "",
                           as_name=args.as_name)
    except RulePackError as exc:
        print(f"规则包错误：{exc}", file=sys.stderr)
        return 2
    print(f"已发布规则包 {pack.id}（不可变）")
    print(f"快照：{pack.path}")
    print(f"适用：{'、'.join(pack.projects) or '全部项目'} / "
          f"{'、'.join(STAGE_CN.get(s, s) for s in pack.stages) or '全部阶段'}")
    print(f"指纹：{pack.content_hash}")
    return 0


def _cmd_rulepack_template(args) -> int:
    if os.path.exists(args.path):
        print(f"已存在同名文件，未覆盖：{args.path}", file=sys.stderr)
        return 2
    content = new_draft(
        args.name, projects=args.project or [], stages=args.stage or [],
        threshold_profile=args.profile)
    write_draft_template(args.path, content)
    print(f"规则包草稿模板已生成：{args.path}")
    print("编辑后发布：python -m ifc_audit.cli rulepack publish "
          f"{args.path} 1.0.0 --as-name {args.name}")
    return 0


def _cmd_rulepack_deprecate(args) -> int:
    lib = _rule_lib(args)
    try:
        lib.set_deprecated(args.name, args.version, not args.undo)
    except RulePackError as exc:
        print(f"规则包错误：{exc}", file=sys.stderr)
        return 2
    action = "废止" if not args.undo else "取消废止"
    print(f"已{action}规则包 {args.name}@{args.version}")
    return 0


def _resolve_materialized(args, optional: bool = False) -> tuple[object, int]:
    """按命令行参数解析并物化规则包；失败返回 (None, 退出码)。

    optional=True 时（批量自动选择），库不存在 / 无适用规则包等“未配置”
    情况返回 (None, 0) 由调用方回退普通模式；显式指定的错误仍然报错。
    """
    lib = _rule_lib(args)
    try:
        if getattr(args, "rule_pack", None):
            pack = resolve_rule_pack(args.rule_pack, lib)
        else:
            pack = lib.select_for(args.project, getattr(args, "stage", "") or "")
        return materialize(pack), 0
    except RulePackError as exc:
        if optional and not getattr(args, "rule_pack", None):
            if not args.quiet:
                print(f"[info] 未使用企业规则包（{exc}），改用内置预设。")
            return None, 0
        print(f"规则包错误：{exc}", file=sys.stderr)
        return None, 2


def _rule_pack_conflict_items(args, include_gate: bool = True) -> list[str]:
    """与规则包口径互斥的手动参数（保证“按哪个版本核查”可追溯）。

    include_gate=False 用于没有门禁参数的 audit 子命令。
    """
    items = []
    if getattr(args, "profile", "default") != "default":
        items.append(f"--profile {args.profile}")
    if getattr(args, "config", None):
        items.append(f"--config {args.config}")
    if getattr(args, "set_threshold", None):
        items.append("--set")
    if include_gate:
        if getattr(args, "no_gate", False):
            items.append("--no-gate")
        if getattr(args, "gate_profile", "default") != "default":
            items.append(f"--gate-profile {args.gate_profile}")
        if getattr(args, "gate_config", None):
            items.append("--gate-config")
        if getattr(args, "gate_set", None):
            items.append("--gate-set")
    return items


def _resolve_rule_pack_for_run(args, auto: bool,
                               include_gate: bool = True,
                               escape_hint: str = "") -> tuple[object, int]:
    """audit / batch 共用的规则包选择 + 冲突判定。

    流程：先判断是否要用规则包（显式 ``--rule-pack`` 优先；否则按
    ``auto`` 决定是否按项目/阶段自动选择），**确认实际选到规则包后**再
    检查手动阈值 / 门禁参数冲突——自动选包没有适用包而回退普通模式时，
    普通参数照常生效，不算冲突。

    Args:
        escape_hint: 自动选包冲突时给出的“改用临时口径”操作提示
            （batch 为 ``--no-rule-pack``，audit 为去掉 ``--use-rule-pack``）。

    Returns:
        (mat, rc)：``(None, 0)`` 表示本次不用规则包（调用方走普通模式）；
        ``(mat, 0)`` 为已物化规则包；``(None, 2)`` 表示冲突或规则包错误。
    """
    explicit = bool(getattr(args, "rule_pack", None))
    if not (explicit or auto):
        return None, 0
    if explicit and getattr(args, "no_rule_pack", False):
        print("配置冲突：--rule-pack 与 --no-rule-pack 不能同时使用。",
              file=sys.stderr)
        return None, 2
    # 自动选择允许“无适用包”回退；显式指定时任何错误都退出码 2
    mat, rc = _resolve_materialized(args, optional=not explicit)
    if rc or mat is None:
        return mat, rc
    # 已选到规则包：手动阈值/门禁参数不得再覆盖口径，否则报告虽标注版本、
    # 实际口径却不是该版本，追溯链断裂
    conflicts = _rule_pack_conflict_items(args, include_gate=include_gate)
    if conflicts:
        esc = f"\n  · {escape_hint}；" if (auto and escape_hint) else ""
        print(
            f"配置冲突：本次已{'显式指定' if explicit else '按项目/阶段自动选用'}"
            f"企业规则包 {mat.ref.id}，不允许同时指定 "
            f"{'、'.join(conflicts)}。\n"
            "  · 要按规则包口径核查/放行：去掉上述冲突参数；"
            f"{esc}"
            "\n  · 需要不同的阈值或放行条件（含本次不阻断放行）："
            "请调整并发布新版本的规则包（版本化留痕，可追溯）。",
            file=sys.stderr)
        return None, 2
    return mat, 0


def _cmd_audit(args) -> int:
    out_dir = args.output
    base = os.path.splitext(os.path.basename(args.ifc))[0]

    def progress(pct, msg):
        if not args.quiet:
            print(f"[{pct:3d}%] {msg}", flush=True)

    try:
        overrides = parse_set_items(args.set_threshold)
        auto = bool(getattr(args, "use_rule_pack", False))
        mat, rc = _resolve_rule_pack_for_run(
            args, auto=auto, include_gate=False,
            escape_hint=("本次确实要改用命令行临时口径：去掉 --use-rule-pack"
                         "（该次核查不标注规则包版本，不作为企业口径留痕）"))
        if rc:
            return rc
        # 口径确定且无冲突后才创建输出目录
        os.makedirs(out_dir, exist_ok=True)
        if mat is not None:
            model = audit_ifc(
                args.ifc, progress=progress if not args.quiet else None,
                thresholds=mat.thresholds,
                provenance=mat.threshold_provenance,
                enabled_kinds=mat.enabled_kinds, rule_pack=mat.ref)
            pack_info = mat.ref
        else:
            model = audit_ifc_with_config(
                args.ifc, progress=progress if not args.quiet else None,
                profile=args.profile, config_path=args.config,
                overrides=overrides or None)
            pack_info = None
    except ThresholdConfigError as exc:
        print(f"阈值配置错误：{exc}", file=sys.stderr)
        return 2
    s = model.summary()

    print("\n================ 核查汇总 ================")
    print(f"文件        : {s['file']}")
    if pack_info is not None:
        print(f"规则包      : {pack_info.describe()}")
        print(f"规则包指纹  : {pack_info.content_hash}")
    print(f"墙体/门/窗  : {s['walls']} / {s['doors']} / {s['windows']}")
    print(f"房间        : {s['rooms']}    净面积合计: {s['total_net_area']} m²")
    print(f"问题        : {s['issues']} 条 (错误 {s['errors']} / 警告 {s['warnings']})")
    print(f"重复构件组  : {s['duplicate_groups']}")
    print(f"阈值方案    : {model.threshold_provenance.describe()}")

    if model.issues:
        print("\n---------------- 问题清单 ----------------")
        for n, i in enumerate(model.issues, start=1):
            print(f"{n:>3}. {i.issue_id} [{SEV_CN.get(i.severity, i.severity)}] "
                  f"{KIND_CN.get(i.kind, i.kind)} | {i.title}"
                  f"{f'  ({i.storey})' if i.storey else ''}")

    print("\n---------------- 房间净面积 --------------")
    print(f"{'房间':<14}{'楼层':<10}{'净面积m²':>10}{'来源':>8}"
          f"{'门':>4}{'窗':>4}  围护状态")
    for r in model.rooms:
        print(f"{(r.name or '')[:14]:<14}{(r.storey or '')[:10]:<10}"
              f"{r.net_area:>10.2f}{('声明' if r.area_source == 'declared' else '几何'):>8}"
              f"{r.doors:>4}{r.windows:>4}  {r.enclosure_label}")

    print("\n---------------- 门窗表 ------------------")
    from .openings import size_label
    print(f"{'楼层':<8}{'房间':<14}{'类':<4}{'类型':<10}"
          f"{'规格(mm)':<12}{'数量':>4}  备注")
    for r in model.opening_schedule:
        print(f"{(r.storey or '-')[:8]:<8}{r.room_name[:14]:<14}"
              f"{('门' if r.kind == 'door' else '窗'):<4}"
              f"{(r.type_name or '')[:10]:<10}{size_label(r.width, r.height):<12}"
              f"{r.count:>4}  {r.notes}")

    outputs = {}
    xlsx = os.path.join(out_dir, f"{base}_核查报告.xlsx")
    report.export_excel(model, xlsx)
    outputs["excel"] = xlsx

    report.export_issues_csv(model, os.path.join(out_dir, f"{base}_问题清单.csv"))
    report.export_rooms_csv(model, os.path.join(out_dir, f"{base}_房间净面积.csv"))
    outputs["issues_csv"] = os.path.join(out_dir, f"{base}_问题清单.csv")
    outputs["rooms_csv"] = os.path.join(out_dir, f"{base}_房间净面积.csv")

    report.export_openings_csv(model, os.path.join(out_dir, f"{base}_门窗表.csv"))
    outputs["openings_csv"] = os.path.join(out_dir, f"{base}_门窗表.csv")

    plan = os.path.join(out_dir, f"{base}_标注平面图.png")
    report.export_annotated_plan(model, plan)
    outputs["annotated_plan"] = plan

    # 三维图：优先 pyvista 离屏渲染；无 GL/显示环境自动降级 matplotlib
    view3d = os.path.join(out_dir, f"{base}_三维标注.png")
    try:
        from .viewer import Viewer3D, offscreen_render_available, matplotlib_screenshot
        if offscreen_render_available():
            Viewer3D(model).screenshot(view3d)
        else:
            if not args.quiet:
                print("[info] 当前环境无 GPU/显示，三维图改用 matplotlib 渲染；"
                      "在桌面环境运行 `python -m ifc_audit.cli gui` 可使用 PyVista 交互定位。")
            matplotlib_screenshot(model, view3d)
    except Exception as exc:
        if not args.quiet:
            print(f"[warn] 三维渲染失败（{exc}），改用 matplotlib。")
        from .viewer import matplotlib_screenshot
        matplotlib_screenshot(model, view3d)
    outputs["view3d"] = view3d

    # 机器可读 JSON（GUI / 后续流水线使用）
    from dataclasses import asdict
    dump = {
        "summary": s,
        "rule_pack": pack_info.to_dict() if pack_info is not None else None,
        "thresholds": {
            "values": asdict(model.thresholds) if model.thresholds else None,
            "provenance": (model.threshold_provenance.to_dict()
                           if model.threshold_provenance else None),
        },
        "issues": [
            {
                "id": i.issue_id, "severity": i.severity, "kind": i.kind,
                "title": i.title, "detail": i.detail,
                "global_ids": i.global_ids,
                "location": list(i.location), "storey": i.storey,
                "measure": i.measure,
            } for i in model.issues
        ],
        "rooms": [vars(r) for r in model.rooms],
        "openings": {
            "items": [vars(o) for o in model.opening_items],
            "schedule": [vars(r) for r in model.opening_schedule],
        },
        "outputs": outputs,
    }
    json_path = os.path.join(out_dir, f"{base}_结果.json")
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(dump, f, ensure_ascii=False, indent=2, default=str)

    print("\n---------------- 导出文件 ----------------")
    for k, v in outputs.items():
        print(f"{k:<16}: {v}")
    print(f"{'json':<16}: {json_path}")

    return 1 if (s["errors"] > 0 and args.fail_on_error) else 0


def _print_batch_summary(batch) -> None:
    t = batch.totals
    print("\n============== 项目批量核查汇总 ==============")
    print(f"项目        : {batch.project}")
    print(f"批次        : {batch.batch_id} {batch.label or ''}（{batch.created_at}）")
    print(f"纳入单体    : {t['units']} 个（成功 {t['units'] - t['units_failed']}"
          f" / 失败 {t['units_failed']}）")
    print(f"构件(墙门窗房间): {t['walls']} / {t['doors']} / "
          f"{t['windows']} / {t['rooms']}")
    print(f"问题        : {t['issues']} 条 (错误 {t['errors']} / "
          f"警告 {t['warnings']} / 提示 {t['infos']})")
    print(f"重复构件组  : {t['duplicate_groups']}")
    print(f"净面积合计  : {t['total_net_area']} m2；不闭合房间 {t['rooms_open']} 间")
    print(f"门窗        : 共 {t['opening_total']} 樘，"
          f"尺寸异常 {t['opening_anomaly']}，未归属 {t['opening_unassigned']}")
    if batch.rule_pack:
        print(f"规则包      : {batch.rule_pack['id']}（指纹 {batch.rule_pack['content_hash']}）")
    print(f"核查阈值    : {next((u.threshold_describe for u in batch.units if u.ok), '-')}")
    print(f"门禁方案    : {batch.gate.get('description') or '-'}")

    print("\n---------------- 单体汇总 ----------------")
    print(f"{'单体':<16}{'状态':<6}{'错误':>5}{'警告':>5}"
          f"{'重复组':>7}{'净面积m²':>11}{'不闭合':>7}{'异常门窗':>8}")
    for u in batch.units:
        if not u.ok:
            print(f"{u.name[:16]:<16}{'失败':<6}  {u.error}")
            continue
        print(f"{u.name[:16]:<16}{'成功':<6}{u.errors:>5}{u.warnings:>5}"
              f"{u.dup_groups:>7}{u.total_net_area:>11.2f}"
              f"{u.rooms_open:>7}{u.opening_anomaly:>8}")

    fails = [r for r in batch.gate_results if not r.passed]
    if fails:
        print("\n---------------- 门禁未通过项 ----------------")
        level_cn = {"unit": "单体", "project": "项目", "batch": "批次"}
        for r in fails:
            print(f"✗ [{level_cn.get(r.level, r.level)}] {r.scope}：{r.message}")

    tr = batch.trend or {}
    if tr.get("has_previous"):
        print("\n---------------- 趋势对比（相对上一批次）----------------")
        print(f"上一批次：{tr.get('previous_batch_id')} "
              f"{tr.get('previous_label') or ''}（{tr.get('previous_created_at')}）")
        prev_pack = tr.get("previous_rule_pack_id") or ""
        cur_pack = (batch.rule_pack or {}).get("id", "")
        if cur_pack or prev_pack:
            if cur_pack == prev_pack:
                print(f"规则包    : {cur_pack or '未使用'}（与上一批次一致）")
            else:
                print(f"规则包    : {prev_pack or '未使用（内置预设）'} → "
                      f"{cur_pack or '未使用（内置预设）'}（版本已切换，指标口径可能变化）")
        for key, d in tr.get("deltas", {}).items():
            delta = d["delta"]
            if delta == 0:
                arrow = "持平"
            else:
                arrow = f"{'增加' if delta > 0 else '减少'} {abs(delta):g}"
            print(f"  {d['label']:<12} {d['old']:g} → {d['new']:g}  （{arrow}）")
        if tr.get("units_new") or tr.get("units_missing"):
            print(f"  新增单体：{', '.join(tr['units_new']) or '无'}；"
                  f"本批缺失：{', '.join(tr['units_missing']) or '无'}")

    print("\n放行结论：" + ("✅ 准予放行" if batch.gate_passed
                           else "⛔ 不予放行（质量门禁阻断）"))


def _safe_unit_filename(name: str) -> str:
    """单体名 -> 可安全作为文件名的字符串（去掉路径分隔符等非法字符）。"""
    return re.sub(r'[\\/:*?"<>|]+', "_", name).strip("_") or "unit"


def _export_unit_reports(batch, out_dir, quiet, with_3d) -> None:
    """为每个成功核查的单体导出单模型 Excel/CSV/平面图（可选三维图）。"""
    sub = os.path.join(out_dir, "单体报告")
    os.makedirs(sub, exist_ok=True)
    used_names: set[str] = set()
    for u in batch.units:
        if u.model is None:
            continue
        # 不同目录同名单体已在批量入口消歧；这里再做一次文件名防御，绝不覆盖
        base = _safe_unit_filename(u.name)
        if base in used_names:
            i = 2
            while f"{base}-{i}" in used_names:
                i += 1
            base = f"{base}-{i}"
        used_names.add(base)
        report.export_excel(u.model, os.path.join(sub, f"{base}_核查报告.xlsx"))
        report.export_issues_csv(u.model, os.path.join(sub, f"{base}_问题清单.csv"))
        report.export_rooms_csv(u.model, os.path.join(sub, f"{base}_房间净面积.csv"))
        report.export_openings_csv(u.model, os.path.join(sub, f"{base}_门窗表.csv"))
        report.export_annotated_plan(
            u.model, os.path.join(sub, f"{base}_标注平面图.png"))
        if with_3d:
            view3d = os.path.join(sub, f"{base}_三维标注.png")
            try:
                from .viewer import (
                    Viewer3D, offscreen_render_available, matplotlib_screenshot)
                if offscreen_render_available():
                    Viewer3D(u.model).screenshot(view3d)
                else:
                    matplotlib_screenshot(u.model, view3d)
            except Exception as exc:
                if not quiet:
                    print(f"[warn] {u.name} 三维渲染失败（{exc}），跳过。")
        if not quiet:
            print(f"  已导出单体报告：{base}")


def _cmd_batch(args) -> int:
    out_dir = args.output
    history_dir = args.history or os.path.join("output", "batch_history")

    def progress(pct, msg):
        if not args.quiet:
            print(f"[{pct:3d}%] {msg}", flush=True)

    try:
        overrides = parse_set_items(args.set_threshold)
        gate_overrides = parse_gate_set_items(args.gate_set)
        # 批量默认按项目/阶段自动选包；--no-rule-pack 显式关闭自动选择。
        # 显式 --rule-pack 与自动选包共用同一套冲突判定（含 --no-gate）。
        auto = getattr(args, "use_rule_pack", True) \
            and not getattr(args, "no_rule_pack", False)
        mat, rc = _resolve_rule_pack_for_run(
            args, auto=auto, include_gate=True,
            escape_hint=("本次确实要改用命令行临时口径：显式加 --no-rule-pack"
                         "（该次报告不标注规则包版本，不作为企业口径留痕）"))
        if rc:
            return rc
        # 口径已确定（规则包或普通参数）且无冲突，才创建输出目录并执行
        os.makedirs(out_dir, exist_ok=True)
        if mat is not None:
            batch = run_batch_with_rule_pack(
                args.paths, mat,
                project=args.project, label=args.label or "",
                progress=progress if not args.quiet else None)
        else:
            batch = run_batch_with_config(
                args.paths,
                project=args.project,
                label=args.label or "",
                threshold_profile=args.profile,
                threshold_config=args.config,
                threshold_overrides=overrides or None,
                gate_profile=("none" if args.no_gate else args.gate_profile),
                gate_config=(None if args.no_gate else args.gate_config),
                gate_overrides=(None if args.no_gate else (gate_overrides or None)),
                progress=progress if not args.quiet else None)
        attach_trend(batch, history_dir)
    except (ThresholdConfigError, GateConfigError, RulePackError) as exc:
        print(f"配置错误：{exc}", file=sys.stderr)
        return 2
    except FileNotFoundError as exc:
        print(f"批量核查失败：{exc}", file=sys.stderr)
        return 2

    if not args.quiet:
        _print_batch_summary(batch)

    # 导出：批次 Excel / 看板 PNG / JSON + 单体报告
    xlsx = batch_report.export_batch_excel(
        batch, os.path.join(out_dir, f"{args.project}_批次核查报告_{batch.batch_id}.xlsx"))
    png = batch_report.export_dashboard(
        batch, os.path.join(out_dir, f"{args.project}_质量看板_{batch.batch_id}.png"))
    jpath = batch_report.export_batch_json(
        batch, os.path.join(out_dir, f"{args.project}_批次结果_{batch.batch_id}.json"))

    if not args.no_unit_reports:
        if not args.quiet:
            print("\n---------------- 导出单体报告 ----------------")
        _export_unit_reports(batch, out_dir, args.quiet, args.with_3d)

    # 快照留存（批次 JSON 导出后再留存，供后续批次趋势对比）
    snap = save_batch_snapshot(batch, history_dir)

    print("\n---------------- 导出文件 ----------------")
    for label, p in (("批次Excel", xlsx), ("质量看板", png),
                     ("批次JSON", jpath), ("批次快照", snap)):
        print(f"{label:<10}: {p}")

    if not batch.gate_passed:
        print("\n质量门禁未通过，已阻断放行。"
              "可调整模型后重新核查，或用 --gate-profile loose/--no-gate 临时放行。",
              file=sys.stderr)
        return 3
    return 0


def _cmd_trend(args) -> int:
    history = load_project_history(
        args.history or os.path.join("output", "batch_history"), args.project)
    if not history:
        print(f"项目“{args.project}”没有历史批次记录。", file=sys.stderr)
        return 2
    print(f"项目“{args.project}”共 {len(history)} 个批次：\n")
    print(f"{'批次':<18}{'标签':<12}{'规则包':<22}{'时间':<22}"
          f"{'单体':>4}{'问题':>5}{'错误':>5}{'警告':>5}  放行")
    for h in history:
        pack_id = h.get("rule_pack_id") or (h.get("rule_pack") or {}).get("id") \
            or "(内置预设)"
        print(f"{h.get('batch_id', ''):<20}{(h.get('label') or '-'):<12}"
              f"{pack_id:<24}{h.get('created_at', ''):<22}"
              f"{h.get('n_files', h.get('n_units', 0)):>4}"
              f"{h.get('totals', {}).get('issues', h.get('issues', 0)):>5}"
              f"{h.get('totals', {}).get('errors', h.get('errors', 0)):>5}"
              f"{h.get('totals', {}).get('warnings', h.get('warnings', 0)):>5}  "
              f"{'✅' if h.get('gate_passed') else '⛔阻断'}")

    if len(history) >= 2:
        first, last = history[0], history[-1]
        ft, lt = first.get("totals", {}), last.get("totals", {})
        print("\n首末批次对比：")
        for key, label in (("issues", "问题总数"), ("errors", "错误"),
                           ("warnings", "警告"), ("duplicate_groups", "重复构件组"),
                           ("total_net_area", "净面积(m²)"),
                           ("rooms_open", "不闭合房间"),
                           ("opening_anomaly", "尺寸异常门窗"),
                           ("opening_unassigned", "未归属门窗")):
            o, n = ft.get(key, 0), lt.get(key, 0)
            d = n - o
            arrow = "持平" if d == 0 else (f"{'+' if d > 0 else ''}{d:g}")
            print(f"  {label:<12} {o:g} → {n:g}  （{arrow}）")

    if args.output:
        # 用历史快照的精简点复用趋势图渲染
        from types import SimpleNamespace
        fake = SimpleNamespace(
            project=args.project, trend={"history": [
                {k: h.get(k) for k in (
                    "batch_id", "label", "created_at", "gate_passed",
                    "issues", "errors", "warnings", "total_net_area")}
                | {"rule_pack_id": h.get("rule_pack_id")
                   or (h.get("rule_pack") or {}).get("id", "")}
                for h in history]})
        p = batch_report.export_trend_chart(fake, args.output)
        print(f"\n趋势图已导出：{p}")
    return 0


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        prog="ifc_audit",
        description="IFC 建筑模型核查工具：未闭合墙 / 重复构件 / 房间净面积 / 门窗表",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_audit = sub.add_parser("audit", help="核查 IFC 文件并导出报告")
    p_audit.add_argument("ifc", help="IFC 文件路径 (.ifc/.ifcxml/.ifczip)")
    p_audit.add_argument("-o", "--output", default="output", help="输出目录")
    p_audit.add_argument("-q", "--quiet", action="store_true", help="精简输出")
    p_audit.add_argument("--fail-on-error", action="store_true",
                         help="存在错误级问题时以退出码 1 返回（便于 CI 集成）")
    p_audit.add_argument(
        "--profile", choices=PROFILES, default="default",
        help="判定阈值预设：default=标准（默认）/ strict=严格 / loose=宽松；"
             "会被配置文件与 --set 覆盖")
    p_audit.add_argument("--config",
                         help="阈值配置 JSON 文件（可用 init-config 生成模板）")
    p_audit.add_argument(
        "--set", dest="set_threshold", action="append", default=[],
        metavar="KEY=VALUE",
                         help="单项覆盖阈值，可重复，长度 mm / 偏差 %%。"
                              "例如 --set gap_min_len_mm=50 --set area_dev_warn_pct=1")
    _add_rule_pack_args(p_audit, auto_flag=True)
    # 单模型自动选择规则包时用项目名匹配；帮助中不突出（主要场景是批量）
    p_audit.add_argument("--project", default="未命名项目", help=argparse.SUPPRESS)
    p_audit.set_defaults(func=_cmd_audit)

    p_gui = sub.add_parser("gui", help="启动图形界面")
    p_gui.set_defaults(func=lambda a: _launch_gui())

    # ---- 多模型批量核查 + 项目质量看板 ----
    p_batch = sub.add_parser(
        "batch",
        help="批量核查多个单体 IFC，按项目/单体/楼层汇总并生成质量看板；"
             "门禁不达标时退出码 3 阻断放行")
    p_batch.add_argument("paths", nargs="+",
                         help="IFC 文件或目录（目录取其中 .ifc/.ifcxml/.ifczip），"
                              "可混合传入多个")
    p_batch.add_argument("--project", default="未命名项目", help="项目名（看板与历史归档用）")
    p_batch.add_argument("--label", default="", help="批次标签，如 “v1提模” / “竣工审查”")
    p_batch.add_argument("-o", "--output", default=os.path.join("output", "batch"),
                         help="批次报告输出目录（默认 output/batch/）")
    p_batch.add_argument("--history", default=None,
                         help="批次历史留存目录（默认 output/batch_history/）")
    p_batch.add_argument("-q", "--quiet", action="store_true", help="精简输出")
    p_batch.add_argument("--with-3d", action="store_true",
                         help="同时导出每个单体的三维标注图（默认仅平面图，批量更快）")
    p_batch.add_argument("--no-unit-reports", action="store_true",
                         help="不导出单体 Excel/CSV/平面图，只出批次报告与看板")
    # 核查阈值（与 audit 子命令一致）
    p_batch.add_argument("--profile", choices=PROFILES, default="default",
                         help="单模型核查阈值预设：default/strict/loose")
    p_batch.add_argument("--config", help="核查阈值配置 JSON（init-config 生成）")
    p_batch.add_argument("--set", dest="set_threshold", action="append",
                         default=[], metavar="KEY=VALUE",
                         help="单项覆盖核查阈值，可重复")
    # 放行门禁
    p_batch.add_argument("--gate-profile", choices=GATE_PROFILES, default="default",
                         help="放行门禁预设：default=标准（默认）/ strict=严格 / "
                              "loose=宽松 / none=不设门禁不阻断")
    p_batch.add_argument("--gate-config", help="门禁配置 JSON（init-gate 生成）")
    p_batch.add_argument("--gate-set", action="append", default=[],
                         metavar="KEY=VALUE",
                         help="单项覆盖门禁规则，可重复，如 "
                              "--gate-set unit_max_warnings=20")
    p_batch.add_argument("--no-gate", action="store_true",
                         help="本次不启用门禁（等同 --gate-profile none，仅统计不阻断）")
    # 企业审查规则包（发布后的规则包按项目/阶段自动匹配，也可显式指定）
    p_batch.add_argument("--rule-lib", default=DEFAULT_RULE_LIBRARY,
                         help=f"企业规则库目录（默认 {DEFAULT_RULE_LIBRARY}）")
    p_batch.add_argument("--rule-pack", default=None,
                         metavar="名称[@版本]|快照.json",
                         help="显式指定企业规则包；不给定时按 --project/--stage "
                              "从规则库自动选择适用的已发布规则包")
    p_batch.add_argument("--stage", choices=STAGES, default="",
                         help="项目阶段（自动选择规则包用）："
                              + " / ".join(f"{k}={v}" for k, v in STAGE_CN.items()))
    p_batch.add_argument("--no-rule-pack", dest="no_rule_pack",
                         action="store_true",
                         help="即使规则库中存在适用规则包也不使用，"
                              "改用 --profile/--gate-profile 等普通参数")
    p_batch.set_defaults(use_rule_pack=True, func=_cmd_batch)

    # ---- 批次历史趋势 ----
    p_trend = sub.add_parser(
        "trend", help="查看项目历史批次趋势对比，可选导出趋势图 PNG")
    p_trend.add_argument("--project", required=True, help="项目名")
    p_trend.add_argument("--history", default=None,
                         help="批次历史目录（默认 output/batch_history/）")
    p_trend.add_argument("-o", "--output", default=None,
                         help="趋势图 PNG 输出路径（不给则只在控制台列出）")
    p_trend.set_defaults(func=_cmd_trend)

    p_init = sub.add_parser(
        "init-config", help="生成带说明的阈值配置文件模板（JSON）")
    p_init.add_argument("path", help="配置文件输出路径，如 thresholds.json")
    p_init.add_argument("--profile", choices=PROFILES, default="default",
                        help="模板以哪套预设值为初始值（默认 default）")
    p_init.set_defaults(func=_cmd_init_config)

    p_init_gate = sub.add_parser(
        "init-gate", help="生成带说明的项目放行门禁配置模板（JSON）")
    p_init_gate.add_argument("path", help="配置文件输出路径，如 gate.json")
    p_init_gate.add_argument("--profile", choices=GATE_PROFILES, default="default",
                             help="模板以哪套门禁预设为初始值（默认 default）")
    p_init_gate.set_defaults(func=_cmd_init_gate)

    # ---- 企业审查规则库 ----
    p_rp = sub.add_parser(
        "rulepack", help="企业审查规则库：规则包草稿 / 发布 / 版本 / 适用范围")
    rp_sub = p_rp.add_subparsers(dest="rulepack_command", required=True)

    p_rp_list = rp_sub.add_parser("list", help="列出规则库内全部规则包与版本")
    p_rp_list.add_argument("--rule-lib", default=DEFAULT_RULE_LIBRARY,
                           help=f"规则库目录（默认 {DEFAULT_RULE_LIBRARY}）")
    p_rp_list.set_defaults(func=_cmd_rulepack_list)

    p_rp_init = rp_sub.add_parser(
        "init", help="在规则库中创建规则包草稿（核查项全开，可再编辑）")
    p_rp_init.add_argument("name", help="规则包名称，如 住宅施工图审查规则")
    p_rp_init.add_argument("--description", default="", help="规则包用途说明")
    p_rp_init.add_argument("--project", action="append", default=[],
                           help="适用项目名，可重复；不给则适用全部项目")
    p_rp_init.add_argument("--stage", choices=STAGES, action="append", default=[],
                           help="适用阶段，可重复；不给则适用全部阶段")
    p_rp_init.add_argument("--profile", choices=PROFILES, default="default",
                           help="以哪套阈值预设为草稿初始值（默认 default）")
    p_rp_init.add_argument("--rule-lib", default=DEFAULT_RULE_LIBRARY,
                           help=f"规则库目录（默认 {DEFAULT_RULE_LIBRARY}）")
    p_rp_init.set_defaults(func=_cmd_rulepack_init)

    p_rp_pub = rp_sub.add_parser(
        "publish", help="发布草稿为不可变版本快照（同名同版本不可重复发布）")
    p_rp_pub.add_argument("source",
                          help="库内规则包名（取其草稿）或草稿 JSON 文件路径")
    p_rp_pub.add_argument("version", help="语义化版本号，如 1.0.0")
    p_rp_pub.add_argument("--as-name", default=None,
                          help="从库外草稿文件发布时指定规则包名称")
    p_rp_pub.add_argument("--by", default="", help="发布人（记录在快照中）")
    p_rp_pub.add_argument("--rule-lib", default=DEFAULT_RULE_LIBRARY,
                          help=f"规则库目录（默认 {DEFAULT_RULE_LIBRARY}）")
    p_rp_pub.set_defaults(func=_cmd_rulepack_publish)

    p_rp_show = rp_sub.add_parser("show", help="查看规则包内容（核查项/阈值/门禁）")
    p_rp_show.add_argument("spec", help="规则包名称、名称@版本或快照 JSON 路径")
    p_rp_show.add_argument("--rule-lib", default=DEFAULT_RULE_LIBRARY,
                           help=f"规则库目录（默认 {DEFAULT_RULE_LIBRARY}）")
    p_rp_show.set_defaults(func=_cmd_rulepack_show)

    p_rp_dep = rp_sub.add_parser(
        "deprecate", help="标记某版本废止（不参与自动选择；快照不删除）")
    p_rp_dep.add_argument("name", help="规则包名称")
    p_rp_dep.add_argument("version", help="版本号")
    p_rp_dep.add_argument("--undo", action="store_true", help="取消废止标记")
    p_rp_dep.add_argument("--rule-lib", default=DEFAULT_RULE_LIBRARY,
                          help=f"规则库目录（默认 {DEFAULT_RULE_LIBRARY}）")
    p_rp_dep.set_defaults(func=_cmd_rulepack_deprecate)

    p_rp_tpl = rp_sub.add_parser(
        "template", help="在任意目录生成带说明的规则包草稿模板 JSON")
    p_rp_tpl.add_argument("path", help="模板输出路径，如 rules.json")
    p_rp_tpl.add_argument("--name", default="企业审查规则包", help="规则包名称")
    p_rp_tpl.add_argument("--project", action="append", default=[],
                          help="适用项目名，可重复；不给则全部项目")
    p_rp_tpl.add_argument("--stage", choices=STAGES, action="append", default=[],
                          help="适用阶段，可重复；不给则全部阶段")
    p_rp_tpl.add_argument("--profile", choices=PROFILES, default="default",
                          help="以哪套阈值预设为初始值（默认 default）")
    p_rp_tpl.set_defaults(func=_cmd_rulepack_template)

    args = parser.parse_args(argv)
    return args.func(args)


def _cmd_init_config(args) -> int:
    if os.path.exists(args.path):
        print(f"已存在同名文件，未覆盖：{args.path}", file=sys.stderr)
        return 2
    write_config_template(args.path, args.profile)
    print(f"阈值配置模板已生成：{args.path}（初始预设：{PROFILE_CN[args.profile]}）")
    print(f"修改后使用：python -m ifc_audit.cli audit model.ifc --config {args.path}")
    return 0


def _cmd_init_gate(args) -> int:
    if os.path.exists(args.path):
        print(f"已存在同名文件，未覆盖：{args.path}", file=sys.stderr)
        return 2
    write_gate_config_template(args.path, args.profile)
    print(f"门禁配置模板已生成：{args.path}（初始预设：{GATE_PROFILE_CN[args.profile]}）")
    print(f"修改后使用：python -m ifc_audit.cli batch ifc目录/ --project 项目名 "
          f"--gate-config {args.path}")
    return 0


def _launch_gui() -> int:
    try:
        from .gui import App
    except Exception as exc:
        print(f"无法启动图形界面：{exc}\n"
              "本机 Python 缺少 tkinter，请安装系统的 python3-tk，"
              "或直接使用 `python -m ifc_audit.cli audit`。", file=sys.stderr)
        return 2
    App().mainloop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
