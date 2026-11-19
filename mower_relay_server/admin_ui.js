'use strict'
const $ = (id) => document.getElementById(id)
let key = ''
let offset = 0
let previousOffsets = []
let users = []
let total = 0
let busy = false
let mode = ''
let selected = null

const hosted = location.pathname !== '/'
$('gatewayPathField').hidden = hosted
let originalEntry = ''

function apiCall(data) {
  if (!hosted) return ['/api', 'POST', { ...data, entry: $('gatewayPath').value.trim() }]
  const users = location.pathname + 'users'
  const subject = data.subject
  switch (data.action) {
    case 'list':
      return [users + '?limit=25&offset=' + (data.offset || 0), 'GET']
    case 'issue':
      return [users, 'POST', { subject, subdomain: data.subdomain }]
    case 'rename':
      return [
        users + '/' + encodeURIComponent(data.subdomain) + '/rename',
        'POST',
        { subject, subdomain: data.new_name },
      ]
    case 'revoke':
      return [users + '/' + encodeURIComponent(data.subdomain) + '/revoke', 'POST', { subject }]
    case 'get_entry':
      return [location.pathname + 'entry', 'GET']
    case 'set_entry':
      return [location.pathname + 'entry', 'PUT', { original: data.original, path: data.path }]
    default:
      throw new Error('不支持的操作')
  }
}

async function request(data, token = key) {
  const [url, method, body] = apiCall(data)
  const response = await fetch(url, {
    method,
    cache: 'no-store',
    credentials: 'omit',
    redirect: 'error',
    headers: { Authorization: 'Bearer ' + token, 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  })
  if (!response.ok) {
    const text = await response.text()
    let detail = ''
    try {
      detail = JSON.parse(text).error
    } catch {
      if (hosted && [400, 409].includes(response.status)) detail = text
    }
    throw new Error(
      detail ||
        {
          403: '管理密钥无效，请重新输入',
          404: '网关未提供该管理接口',
          429: '请求过于频繁，请稍后重试',
        }[response.status] ||
        '网关请求失败',
    )
  }
  return response.json()
}

function controls() {
  document.querySelectorAll('button:not(#issued button)').forEach((button) => {
    button.disabled = busy
  })
  $('prev').disabled = busy || !previousOffsets.length
  $('next').disabled = busy || offset + users.length >= total
}

async function run(errorBox, perform) {
  if (busy) return
  busy = true
  controls()
  errorBox.textContent = ''
  try {
    await perform()
  } catch (err) {
    errorBox.textContent =
      err instanceof TypeError
        ? '未收到管理服务的响应。重新连接后，请先刷新状态核对结果。'
        : err.message
  } finally {
    busy = false
    controls()
  }
}

function actionButton(label, style, handler) {
  const button = document.createElement('button')
  button.type = 'button'
  button.className = 'plain ' + style
  button.textContent = label
  button.onclick = handler
  return button
}

function render() {
  $('rows').replaceChildren()
  for (const user of users) {
    const row = $('rows').insertRow()
    row.insertCell().textContent = user.subdomain
    row.insertCell().textContent = user.subject || '—'
    const state = document.createElement('span')
    state.className = 'state ' + (!user.enabled ? 'revoked' : user.connected ? 'online' : '')
    state.textContent = !user.enabled ? '已吊销' : user.connected ? '已连接' : '未连接'
    row.insertCell().append(state)
    const actions = row.insertCell()
    if (user.enabled) {
      actions.append(
        actionButton('改名', '', () => edit('rename', user)),
        actionButton('吊销', 'danger', () => edit('revoke', user)),
      )
    } else {
      actions.textContent = '—'
    }
  }
  $('empty').hidden = users.length !== 0
  $('count').textContent = total
    ? `第 ${offset + 1}–${offset + users.length} 项，共 ${total} 项`
    : '共 0 项'
  $('updated').textContent = '更新于 ' + new Date().toLocaleTimeString('zh-CN', { hour12: false })
  controls()
}

async function load(target = offset, token = key) {
  const data = await request({ action: 'list', offset: target }, token)
  if (!Array.isArray(data.users) || !Number.isInteger(data.total))
    throw new Error('凭据列表格式无效')
  if (target && !data.users.length) {
    await load(0, token)
    previousOffsets = []
    return
  }
  offset = target
  total = data.total
  users = data.users
  render()
}

$('loginForm').onsubmit = (event) => {
  event.preventDefault()
  run($('loginError'), async () => {
    const input = $('key').value.trim()
    await load(0, input)
    key = input
    $('key').value = ''
    $('login').hidden = true
    $('panel').hidden = false
    $('issue').focus()
  })
}

function logout() {
  key = ''
  previousOffsets = []
  offset = total = 0
  users = []
  selected = null
  $('key').value = $('secret').value = ''
  $('editForm').reset()
  for (const id of ['editor', 'issued', 'entryDialog']) if ($(id).open) $(id).close()
  for (const id of [
    'message',
    'listError',
    'loginError',
    'rows',
    'identity',
    'issuedName',
    'copyStatus',
  ])
    $(id).replaceChildren()
  $('panel').hidden = true
  $('login').hidden = false
  $('key').focus()
}
$('logout').onclick = logout
window.addEventListener('pagehide', logout)
window.addEventListener('pageshow', (event) => {
  if (event.persisted) logout()
})
$('refresh').onclick = () => run($('listError'), () => load())
$('next').onclick = () =>
  run($('listError'), async () => {
    const old = offset
    await load(offset + users.length)
    if (offset > old) previousOffsets.push(old)
  })
$('prev').onclick = () =>
  run($('listError'), async () => {
    await load(previousOffsets.at(-1))
    previousOffsets.pop()
  })

function edit(action, user = null) {
  mode = action
  selected = user
  $('editForm').reset()
  $('editError').textContent = ''
  $('editorTitle').textContent = {
    issue: '签发中转凭据',
    rename: '修改子域名',
    revoke: '吊销凭据',
  }[action]
  $('identity').textContent = user ? user.subdomain + ' · ' + (user.subject || '无用户标识') : ''
  $('effect').textContent = {
    issue: '为一个用户标识分配唯一的子域名。',
    rename: '原凭据继续有效。客户端将重新连接，用户需要打开新地址。',
    revoke: '吊销后当前连接将断开，此凭据无法再次使用。',
  }[action]
  $('nameLabel').hidden = $('name').disabled = action === 'revoke'
  $('subjectLabel').hidden = $('subject').disabled = action !== 'issue'
  $('nameCaption').textContent = action === 'rename' ? '新子域名' : '子域名'
  $('submitEdit').className = action === 'revoke' ? 'danger confirm' : 'primary'
  $('submitEdit').textContent = { issue: '签发', rename: '保存新子域名', revoke: '确认吊销' }[
    action
  ]
  $('editor').showModal()
  ;(action === 'revoke' ? $('cancel') : $('name')).focus()
}
$('issue').onclick = () => edit('issue')
$('cancel').onclick = () => $('editor').close()
$('editor').addEventListener('cancel', (event) => {
  if (busy) event.preventDefault()
})
$('editForm').onsubmit = (event) => {
  event.preventDefault()
  run($('editError'), async () => {
    const name = $('name').value.trim()
    if (mode === 'rename' && name === selected.subdomain) throw new Error('请填写不同的新子域名')
    const payload =
      mode === 'issue'
        ? { action: mode, subdomain: name, subject: $('subject').value.trim() }
        : { action: mode, subdomain: selected.subdomain, subject: selected.subject }
    if (mode === 'rename') payload.new_name = name
    const result = await request(payload)
    $('editor').close()
    $('message').textContent =
      { issue: '已签发', rename: '子域名已更新为', revoke: '已吊销' }[mode] + ' ' + result.subdomain
    if (mode === 'issue') {
      $('issuedName').textContent = result.subdomain + ' · ' + result.subject
      $('secret').value = result.credential
      $('copyStatus').textContent = ''
      $('issued').showModal()
    }
    $('listError').textContent = ''
    try {
      await load()
    } catch (err) {
      $('listError').textContent = '操作已完成，刷新列表失败。请点击刷新状态。'
    }
  })
}
$('issued').addEventListener('close', () => {
  $('secret').value = ''
})
$('issued').addEventListener('cancel', () => {
  $('secret').value = ''
})
$('done').onclick = () => {
  $('secret').value = ''
  $('issued').close()
}
$('copy').onclick = async () => {
  try {
    await navigator.clipboard.writeText($('secret').value)
    $('copyStatus').textContent = '已复制。'
  } catch {
    $('secret').select()
    $('copyStatus').textContent = '已选中凭据，请使用系统复制快捷键。'
  }
}

$('entry').onclick = () =>
  run($('listError'), async () => {
    const data = await request({ action: 'get_entry' })
    originalEntry = data.path
    $('entryPath').value = data.path
    $('entryError').textContent = ''
    $('entryHelp').textContent =
      '保存后网页和管理 API 将立即切换。请同步更新 bot 和其他本机工具的入口路径。'
    $('entryDialog').showModal()
    $('entryPath').focus()
  })
$('entryCancel').onclick = () => $('entryDialog').close()
$('entryDialog').addEventListener('cancel', (event) => {
  if (busy) event.preventDefault()
})
$('entryForm').onsubmit = (event) => {
  event.preventDefault()
  run($('entryError'), async () => {
    const result = await request({
      action: 'set_entry',
      original: originalEntry,
      path: $('entryPath').value.trim(),
    })
    if (hosted) history.replaceState(null, '', result.path)
    else $('gatewayPath').value = result.path
    $('entryDialog').close()
    $('message').textContent = '管理入口已保存：' + 'https://free.mower.work:58000' + result.path
  })
}
