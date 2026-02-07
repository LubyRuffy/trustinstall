import * as React from "react"

import { Button } from "@/components/ui/button"
import { Card, CardContent, CardDescription, CardFooter, CardHeader, CardTitle } from "@/components/ui/card"
import { Field, FieldContent, FieldDescription, FieldGroup, FieldLabel } from "@/components/ui/field"
import { Input } from "@/components/ui/input"
import { Switch } from "@/components/ui/switch"
import { Textarea } from "@/components/ui/textarea"

type InstallCAResponse = {
  ok: boolean
  dir: string
  fileBaseName: string
  commonName: string
  certPath: string
  keyPath: string
  attempts: number
  note?: string
}

type UninstallCAResponse = {
  ok: boolean
  deleted: number
  note?: string
}

async function fetchWithTimeout(url: string, init: RequestInit, timeoutMs: number) {
  const ctl = new AbortController()
  const timer = setTimeout(() => ctl.abort(), timeoutMs)
  try {
    return await fetch(url, { ...init, signal: ctl.signal })
  } finally {
    clearTimeout(timer)
  }
}

async function discoverApiBase(): Promise<string | null> {
  const ports: number[] = []
  for (let p = 34115; p <= 34125; p++) ports.push(p)

  for (const p of ports) {
    const base = `http://127.0.0.1:${p}`
    try {
      const resp = await fetchWithTimeout(`${base}/api/health`, { method: "GET" }, 400)
      if (!resp.ok) continue

      // Avoid false positives: Vite dev server may return 200 HTML for unknown paths.
      const ct = resp.headers.get("content-type") ?? ""
      if (!ct.includes("application/json")) continue

      const data = (await resp.json()) as { ok?: boolean } | null
      if (data?.ok === true) return base
    } catch {
      // ignore
    }
  }
  return null
}

export function App() {
  const [apiBase, setApiBase] = React.useState<string | null>(null)
  const [dir, setDir] = React.useState("")
  const [fileBaseName, setFileBaseName] = React.useState("trustinstall-ca")
  const [commonName, setCommonName] = React.useState("trustinstall-ca")
  const [deleteSame, setDeleteSame] = React.useState(true)
  const [deleteLocal, setDeleteLocal] = React.useState(true)
  const [busy, setBusy] = React.useState(false)
  const [result, setResult] = React.useState<InstallCAResponse | null>(null)
  const [logText, setLogText] = React.useState("")

  React.useEffect(() => {
    let cancelled = false
    ;(async () => {
      const base = await discoverApiBase()
      if (!cancelled) setApiBase(base)
    })()
    return () => {
      cancelled = true
    }
  }, [])

  async function runInstall() {
    setResult(null)
    setLogText("")
    setBusy(true)
    try {
      const base = (apiBase && apiBase.trim()) ? apiBase : await discoverApiBase()
      if (!base || !base.trim()) {
        setLogText("未发现本地 API 服务。请重启应用后再试。")
        return
      }
      setApiBase(base.trim())

      const payload = {
        dir,
        fileBaseName,
        commonName,
        deleteSame,
      }

      const resp = await fetch(`${base}/api/installca`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      })

      const text = await resp.text()
      if (!resp.ok) {
        setLogText(text)
        return
      }

      const json = JSON.parse(text) as InstallCAResponse
      setResult(json)
      setLogText(
        [
          "完成。",
          json.note ? `note: ${json.note}` : "",
          `dir: ${json.dir}`,
          `fileBaseName: ${json.fileBaseName}`,
          `commonName: ${json.commonName}`,
          `cert: ${json.certPath}`,
          `key: ${json.keyPath}`,
          `attempts: ${json.attempts}`,
        ].filter(Boolean).join("\n")
      )
    } catch (e: unknown) {
      setLogText(String(e))
    } finally {
      setBusy(false)
    }
  }

  async function runUninstall() {
    setResult(null)
    setLogText("")
    setBusy(true)
    try {
      const base = (apiBase && apiBase.trim()) ? apiBase : await discoverApiBase()
      if (!base || !base.trim()) {
        setLogText("未发现本地 API 服务。请重启应用后再试。")
        return
      }
      setApiBase(base.trim())

      const payload = {
        commonName,
        deleteLocal,
        dir,
        fileBaseName,
      }

      const resp = await fetch(`${base}/api/uninstallca`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      })

      const text = await resp.text()
      if (!resp.ok) {
        setLogText(text)
        return
      }

      const json = JSON.parse(text) as UninstallCAResponse
      setLogText(
        [
          "完成。",
          json.note ? `note: ${json.note}` : "",
          `commonName: ${commonName}`,
          `deleted: ${json.deleted}`,
        ].filter(Boolean).join("\n")
      )
    } catch (e: unknown) {
      setLogText(String(e))
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="bg-background min-h-screen w-full p-4">
      <Card className="mx-auto w-full max-w-2xl">
        <CardHeader>
          <CardTitle>trustinstall 安装与信任验证</CardTitle>
          <CardDescription>
            调用本机 API 执行 <code>trustinstall.New(...).InstallCA()</code>。在 macOS 的 GUI / 无交互 TTY 场景下会自动弹出一个新的 Terminal 让你输入管理员密码并完成安装与信任设置。
          </CardDescription>
        </CardHeader>
        <CardContent>
          <FieldGroup>
            <Field orientation="responsive">
              <FieldLabel>
                <FieldContent>
                  API 地址
                  <FieldDescription>自动探测 127.0.0.1:34115-34125</FieldDescription>
                </FieldContent>
                <Input value={apiBase ?? ""} readOnly placeholder="未连接" />
              </FieldLabel>
            </Field>

            <Field orientation="responsive">
              <FieldLabel>
                <FieldContent>
                  目录 dir
                  <FieldDescription>留空默认 ~/.trustinstall</FieldDescription>
                </FieldContent>
                <Input value={dir} onChange={(e) => setDir(e.target.value)} placeholder="~/.trustinstall" />
              </FieldLabel>
            </Field>

            <Field orientation="responsive">
              <FieldLabel>
                <FieldContent>
                  fileBaseName
                  <FieldDescription>会生成 .crt/.key</FieldDescription>
                </FieldContent>
                <Input value={fileBaseName} onChange={(e) => setFileBaseName(e.target.value)} />
              </FieldLabel>
            </Field>

            <Field orientation="responsive">
              <FieldLabel>
                <FieldContent>
                  commonName
                  <FieldDescription>用于系统中查找/对比同名证书</FieldDescription>
                </FieldContent>
                <Input value={commonName} onChange={(e) => setCommonName(e.target.value)} />
              </FieldLabel>
            </Field>

            <Field orientation="horizontal">
              <FieldLabel>
                <FieldContent>
                  deleteSame
                  <FieldDescription>删除系统中与本地文件不一致的同名证书</FieldDescription>
                </FieldContent>
                <Switch checked={deleteSame} onCheckedChange={setDeleteSame} />
              </FieldLabel>
            </Field>

            <Field orientation="horizontal">
              <FieldLabel>
                <FieldContent>
                  deleteLocal
                  <FieldDescription>删除本地 .crt/.key（用于重新生成）</FieldDescription>
                </FieldContent>
                <Switch checked={deleteLocal} onCheckedChange={setDeleteLocal} />
              </FieldLabel>
            </Field>

            <Textarea value={logText} readOnly placeholder="运行日志会显示在这里" rows={8} />
          </FieldGroup>
        </CardContent>
        <CardFooter className="gap-2">
          <Button onClick={runInstall} disabled={busy}>
            {busy ? "执行中..." : "安装并设置信任"}
          </Button>
          <Button variant="destructive" onClick={runUninstall} disabled={busy}>
            删除证书
          </Button>
          {result?.certPath ? (
            <Button
              variant="secondary"
              onClick={() => navigator.clipboard.writeText(result.certPath)}
              disabled={busy}
            >
              复制 cert 路径
            </Button>
          ) : null}
        </CardFooter>
      </Card>
    </div>
  )
}

export default App
