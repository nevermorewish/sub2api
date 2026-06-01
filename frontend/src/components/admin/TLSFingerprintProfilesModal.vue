<template>
  <BaseDialog
    :show="show"
    :title="t('admin.tlsFingerprintProfiles.title')"
    width="wide"
    @close="$emit('close')"
  >
    <div class="space-y-4">
      <!-- Header -->
      <div class="flex items-center justify-between">
        <p class="text-sm text-gray-500 dark:text-gray-400">
          {{ t('admin.tlsFingerprintProfiles.description') }}
        </p>
        <div class="flex items-center gap-2">
          <button @click="openGenerateModal" class="btn btn-secondary btn-sm">
            <Icon name="sparkles" size="sm" class="mr-1" />
            {{ t('admin.tlsFingerprintProfiles.createFromParams') }}
          </button>
          <button @click="openCreateModal" class="btn btn-primary btn-sm">
            <Icon name="plus" size="sm" class="mr-1" />
            {{ t('admin.tlsFingerprintProfiles.createProfile') }}
          </button>
        </div>
      </div>

      <!-- Profiles Table -->
      <div v-if="loading" class="flex items-center justify-center py-8">
        <Icon name="refresh" size="lg" class="animate-spin text-gray-400" />
      </div>

      <div v-else-if="profiles.length === 0" class="py-8 text-center">
        <div class="mx-auto mb-4 flex h-12 w-12 items-center justify-center rounded-full bg-gray-100 dark:bg-dark-700">
          <Icon name="shield" size="lg" class="text-gray-400" />
        </div>
        <h4 class="mb-1 text-sm font-medium text-gray-900 dark:text-white">
          {{ t('admin.tlsFingerprintProfiles.noProfiles') }}
        </h4>
        <p class="text-sm text-gray-500 dark:text-gray-400">
          {{ t('admin.tlsFingerprintProfiles.createFirstProfile') }}
        </p>
      </div>

      <div v-else class="max-h-96 overflow-auto rounded-lg border border-gray-200 dark:border-dark-600">
        <table class="min-w-full divide-y divide-gray-200 dark:divide-dark-700">
          <thead class="sticky top-0 bg-gray-50 dark:bg-dark-700">
            <tr>
              <th class="px-3 py-2 text-left text-xs font-medium uppercase text-gray-500 dark:text-gray-400">
                {{ t('admin.tlsFingerprintProfiles.columns.name') }}
              </th>
              <th class="px-3 py-2 text-left text-xs font-medium uppercase text-gray-500 dark:text-gray-400">
                {{ t('admin.tlsFingerprintProfiles.columns.description') }}
              </th>
              <th class="px-3 py-2 text-left text-xs font-medium uppercase text-gray-500 dark:text-gray-400">
                {{ t('admin.tlsFingerprintProfiles.columns.grease') }}
              </th>
              <th class="px-3 py-2 text-left text-xs font-medium uppercase text-gray-500 dark:text-gray-400">
                {{ t('admin.tlsFingerprintProfiles.columns.alpn') }}
              </th>
              <th class="px-3 py-2 text-left text-xs font-medium uppercase text-gray-500 dark:text-gray-400">
                {{ t('admin.tlsFingerprintProfiles.columns.actions') }}
              </th>
            </tr>
          </thead>
          <tbody class="divide-y divide-gray-200 bg-white dark:divide-dark-700 dark:bg-dark-800">
            <tr v-for="profile in profiles" :key="profile.id" class="hover:bg-gray-50 dark:hover:bg-dark-700">
              <td class="px-3 py-2">
                <div class="font-medium text-gray-900 dark:text-white text-sm">{{ profile.name }}</div>
              </td>
              <td class="px-3 py-2">
                <div v-if="profile.description" class="text-sm text-gray-500 dark:text-gray-400 max-w-xs truncate">
                  {{ profile.description }}
                </div>
                <div v-else class="text-xs text-gray-400 dark:text-gray-600">—</div>
              </td>
              <td class="px-3 py-2">
                <Icon
                  :name="profile.enable_grease ? 'check' : 'lock'"
                  size="sm"
                  :class="profile.enable_grease ? 'text-green-500' : 'text-gray-400'"
                />
              </td>
              <td class="px-3 py-2">
                <div v-if="profile.alpn_protocols?.length" class="flex flex-wrap gap-1">
                  <span
                    v-for="proto in profile.alpn_protocols.slice(0, 3)"
                    :key="proto"
                    class="badge badge-primary text-xs"
                  >
                    {{ proto }}
                  </span>
                  <span v-if="profile.alpn_protocols.length > 3" class="text-xs text-gray-500">
                    +{{ profile.alpn_protocols.length - 3 }}
                  </span>
                </div>
                <div v-else class="text-xs text-gray-400 dark:text-gray-600">—</div>
              </td>
              <td class="px-3 py-2">
                <div class="flex items-center gap-1">
                  <button
                    @click="handleEdit(profile)"
                    class="p-1 text-gray-500 hover:text-primary-600 dark:hover:text-primary-400"
                    :title="t('common.edit')"
                  >
                    <Icon name="edit" size="sm" />
                  </button>
                  <button
                    @click="handleDelete(profile)"
                    class="p-1 text-gray-500 hover:text-red-600 dark:hover:text-red-400"
                    :title="t('common.delete')"
                  >
                    <Icon name="trash" size="sm" />
                  </button>
                </div>
              </td>
            </tr>
          </tbody>
        </table>
      </div>
    </div>

    <template #footer>
      <div class="flex justify-end">
        <button @click="$emit('close')" class="btn btn-secondary">
          {{ t('common.close') }}
        </button>
      </div>
    </template>

    <!-- Create/Edit Modal -->
    <BaseDialog
      :show="showCreateModal || showEditModal"
      :title="showEditModal ? t('admin.tlsFingerprintProfiles.editProfile') : t('admin.tlsFingerprintProfiles.createProfile')"
      width="wide"
      :z-index="60"
      @close="closeFormModal"
    >
      <form @submit.prevent="handleSubmit" class="space-y-4">
        <!-- Paste YAML -->
        <div>
          <label class="input-label">{{ t('admin.tlsFingerprintProfiles.form.pasteYaml') }}</label>
          <textarea
            v-model="yamlInput"
            rows="4"
            class="input font-mono text-xs"
            :placeholder="t('admin.tlsFingerprintProfiles.form.pasteYamlPlaceholder')"
            @paste="handleYamlPaste"
          />
          <div class="mt-1 flex items-center gap-2">
            <button type="button" @click="parseYamlInput" class="btn btn-secondary btn-sm">
              {{ t('admin.tlsFingerprintProfiles.form.parseYaml') }}
            </button>
            <p class="text-xs text-gray-500 dark:text-gray-400">
              {{ t('admin.tlsFingerprintProfiles.form.pasteYamlHint') }}
              <a href="https://tls.sub2api.org" target="_blank" rel="noopener noreferrer" class="text-primary-600 hover:text-primary-700 dark:text-primary-400 dark:hover:text-primary-300 underline">{{ t('admin.tlsFingerprintProfiles.form.openCollector') }}</a>
            </p>
          </div>
        </div>

        <!-- Basic Info -->
        <div class="grid grid-cols-2 gap-4">
          <div>
            <label class="input-label">{{ t('admin.tlsFingerprintProfiles.form.name') }}</label>
            <input
              v-model="form.name"
              type="text"
              required
              class="input"
              :placeholder="t('admin.tlsFingerprintProfiles.form.namePlaceholder')"
            />
          </div>
          <div>
            <label class="input-label">{{ t('admin.tlsFingerprintProfiles.form.description') }}</label>
            <input
              v-model="form.description"
              type="text"
              class="input"
              :placeholder="t('admin.tlsFingerprintProfiles.form.descriptionPlaceholder')"
            />
          </div>
        </div>

        <!-- GREASE Toggle -->
        <div class="flex items-center gap-3">
          <button
            type="button"
            @click="form.enable_grease = !form.enable_grease"
            :class="[
              'relative inline-flex h-5 w-9 flex-shrink-0 cursor-pointer rounded-full border-2 border-transparent transition-colors duration-200 ease-in-out focus:outline-none focus:ring-2 focus:ring-primary-500 focus:ring-offset-2',
              form.enable_grease ? 'bg-primary-600' : 'bg-gray-200 dark:bg-dark-600'
            ]"
          >
            <span
              :class="[
                'pointer-events-none inline-block h-4 w-4 transform rounded-full bg-white shadow ring-0 transition duration-200 ease-in-out',
                form.enable_grease ? 'translate-x-4' : 'translate-x-0'
              ]"
            />
          </button>
          <div>
            <span class="text-sm font-medium text-gray-700 dark:text-gray-300">
              {{ t('admin.tlsFingerprintProfiles.form.enableGrease') }}
            </span>
            <p class="text-xs text-gray-500 dark:text-gray-400">
              {{ t('admin.tlsFingerprintProfiles.form.enableGreaseHint') }}
            </p>
          </div>
        </div>

        <!-- TLS Array Fields - 2 column grid -->
        <div class="grid grid-cols-2 gap-4">
          <div>
            <label class="input-label text-xs">{{ t('admin.tlsFingerprintProfiles.form.cipherSuites') }}</label>
            <textarea
              v-model="fieldInputs.cipher_suites"
              rows="2"
              class="input font-mono text-xs"
              :placeholder="'0x1301, 0x1302, 0xc02c'"
            />
            <p class="input-hint text-xs">{{ t('admin.tlsFingerprintProfiles.form.cipherSuitesHint') }}</p>
          </div>

          <div>
            <label class="input-label text-xs">{{ t('admin.tlsFingerprintProfiles.form.curves') }}</label>
            <textarea
              v-model="fieldInputs.curves"
              rows="2"
              class="input font-mono text-xs"
              :placeholder="'29, 23, 24'"
            />
            <p class="input-hint text-xs">{{ t('admin.tlsFingerprintProfiles.form.curvesHint') }}</p>
          </div>

          <div>
            <label class="input-label text-xs">{{ t('admin.tlsFingerprintProfiles.form.signatureAlgorithms') }}</label>
            <textarea
              v-model="fieldInputs.signature_algorithms"
              rows="2"
              class="input font-mono text-xs"
              :placeholder="'0x0403, 0x0804, 0x0401'"
            />
          </div>

          <div>
            <label class="input-label text-xs">{{ t('admin.tlsFingerprintProfiles.form.supportedVersions') }}</label>
            <textarea
              v-model="fieldInputs.supported_versions"
              rows="2"
              class="input font-mono text-xs"
              :placeholder="'0x0304, 0x0303'"
            />
          </div>

          <div>
            <label class="input-label text-xs">{{ t('admin.tlsFingerprintProfiles.form.keyShareGroups') }}</label>
            <textarea
              v-model="fieldInputs.key_share_groups"
              rows="2"
              class="input font-mono text-xs"
              :placeholder="'29, 23'"
            />
          </div>

          <div>
            <label class="input-label text-xs">{{ t('admin.tlsFingerprintProfiles.form.extensions') }}</label>
            <textarea
              v-model="fieldInputs.extensions"
              rows="2"
              class="input font-mono text-xs"
              :placeholder="'0x0000, 0x0005, 0x000a'"
            />
          </div>

          <div>
            <label class="input-label text-xs">{{ t('admin.tlsFingerprintProfiles.form.pointFormats') }}</label>
            <textarea
              v-model="fieldInputs.point_formats"
              rows="2"
              class="input font-mono text-xs"
              :placeholder="'0'"
            />
          </div>

          <div>
            <label class="input-label text-xs">{{ t('admin.tlsFingerprintProfiles.form.pskModes') }}</label>
            <textarea
              v-model="fieldInputs.psk_modes"
              rows="2"
              class="input font-mono text-xs"
              :placeholder="'1'"
            />
          </div>
        </div>

        <!-- ALPN Protocols - full width -->
        <div>
          <label class="input-label text-xs">{{ t('admin.tlsFingerprintProfiles.form.alpnProtocols') }}</label>
          <textarea
            v-model="fieldInputs.alpn_protocols"
            rows="2"
            class="input font-mono text-xs"
            :placeholder="'h2, http/1.1'"
          />
        </div>
      </form>

      <template #footer>
        <div class="flex justify-end gap-3">
          <button @click="closeFormModal" type="button" class="btn btn-secondary">
            {{ t('common.cancel') }}
          </button>
          <button @click="handleSubmit" :disabled="submitting" class="btn btn-primary">
            <Icon v-if="submitting" name="refresh" size="sm" class="mr-1 animate-spin" />
            {{ showEditModal ? t('common.update') : t('common.create') }}
          </button>
        </div>
      </template>
    </BaseDialog>

    <!-- Generate from Parameters Modal -->
    <BaseDialog
      :show="showGenerateModal"
      :title="t('admin.tlsFingerprintProfiles.createFromParams')"
      width="wide"
      :z-index="60"
      @close="closeGenerateModal"
    >
      <form @submit.prevent="handleGenerateSubmit" class="space-y-4">
        <p class="text-sm text-gray-500 dark:text-gray-400">
          {{ t('admin.tlsFingerprintProfiles.form.generateFromParamsHint') }}
        </p>

        <div class="grid grid-cols-2 gap-4">
          <div>
            <label class="input-label">{{ t('admin.tlsFingerprintProfiles.form.name') }}</label>
            <input
              v-model="generatorForm.name"
              type="text"
              required
              class="input"
              :placeholder="t('admin.tlsFingerprintProfiles.form.namePlaceholder')"
            />
          </div>
          <div>
            <label class="input-label">{{ t('admin.tlsFingerprintProfiles.form.description') }}</label>
            <input
              v-model="generatorForm.description"
              type="text"
              class="input"
              :placeholder="t('admin.tlsFingerprintProfiles.form.descriptionPlaceholder')"
            />
          </div>
        </div>

        <div class="grid grid-cols-2 gap-3 md:grid-cols-4">
          <div>
            <label class="input-label text-xs">{{ t('admin.tlsFingerprintProfiles.form.runtime') }}</label>
            <select v-model="generatorForm.runtime" class="input text-sm">
              <option value="node">Node.js</option>
              <option value="bun">Bun</option>
            </select>
          </div>
          <div>
            <label class="input-label text-xs">{{ t('admin.tlsFingerprintProfiles.form.runtimeVersion') }}</label>
            <input v-model="generatorForm.runtime_version" type="text" class="input text-sm" placeholder="v24.3.0" />
          </div>
          <div>
            <label class="input-label text-xs">{{ t('admin.tlsFingerprintProfiles.form.nodeMajor') }}</label>
            <input v-model.number="generatorForm.node_major" type="number" min="0" class="input text-sm" placeholder="24" />
          </div>
          <div>
            <label class="input-label text-xs">{{ t('admin.tlsFingerprintProfiles.form.openSSLVersion') }}</label>
            <input v-model="generatorForm.openssl_version" type="text" class="input text-sm" placeholder="3.x" />
          </div>
          <div>
            <label class="input-label text-xs">{{ t('admin.tlsFingerprintProfiles.form.transport') }}</label>
            <select v-model="generatorForm.transport" class="input text-sm">
              <option value="fetch">fetch</option>
              <option value="websocket">WebSocket</option>
              <option value="h2">HTTP/2</option>
            </select>
          </div>
          <div>
            <label class="input-label text-xs">{{ t('admin.tlsFingerprintProfiles.form.httpClient') }}</label>
            <input v-model="generatorForm.http_client" type="text" class="input text-sm" placeholder="undici/fetch" />
          </div>
          <div>
            <label class="input-label text-xs">{{ t('admin.tlsFingerprintProfiles.form.webSocketClient') }}</label>
            <input v-model="generatorForm.websocket_client" type="text" class="input text-sm" placeholder="ws" />
          </div>
          <div>
            <label class="input-label text-xs">{{ t('admin.tlsFingerprintProfiles.form.proxyMode') }}</label>
            <select v-model="generatorForm.proxy_mode" class="input text-sm">
              <option value="none">none</option>
              <option value="http_connect">HTTP CONNECT</option>
              <option value="socks5">SOCKS5</option>
            </select>
          </div>
          <div>
            <label class="input-label text-xs">{{ t('admin.tlsFingerprintProfiles.form.greaseMode') }}</label>
            <select v-model="generatorForm.enable_grease" class="input text-sm">
              <option value="auto">{{ t('admin.tlsFingerprintProfiles.form.greaseAuto') }}</option>
              <option value="true">{{ t('common.enabled') }}</option>
              <option value="false">{{ t('common.disabled') }}</option>
            </select>
          </div>
          <div class="col-span-2">
            <label class="input-label text-xs">{{ t('admin.tlsFingerprintProfiles.form.alpnOverride') }}</label>
            <input v-model="generatorForm.alpn_protocols" type="text" class="input text-sm" placeholder="h2, http/1.1" />
          </div>
          <label class="flex items-center gap-2 text-sm text-gray-700 dark:text-gray-300">
            <input v-model="generatorForm.mtls_enabled" type="checkbox" class="rounded border-gray-300 text-primary-600 focus:ring-primary-500" />
            {{ t('admin.tlsFingerprintProfiles.form.mtlsEnabled') }}
          </label>
          <label class="flex items-center gap-2 text-sm text-gray-700 dark:text-gray-300">
            <input v-model="generatorForm.custom_ca_enabled" type="checkbox" class="rounded border-gray-300 text-primary-600 focus:ring-primary-500" />
            {{ t('admin.tlsFingerprintProfiles.form.customCAEnabled') }}
          </label>
        </div>

        <div v-if="generatedNotes.length" class="rounded bg-amber-50 p-2 text-xs text-amber-800 dark:bg-amber-900/20 dark:text-amber-300">
          <div class="font-medium">{{ t('admin.tlsFingerprintProfiles.form.generationNotes') }}</div>
          <ul class="mt-1 list-disc space-y-1 pl-4">
            <li v-for="note in generatedNotes" :key="note">{{ note }}</li>
          </ul>
        </div>
      </form>

      <template #footer>
        <div class="flex justify-end gap-3">
          <button @click="closeGenerateModal" type="button" class="btn btn-secondary">
            {{ t('common.cancel') }}
          </button>
          <button @click="handleGenerateSubmit" :disabled="generating" class="btn btn-primary">
            <Icon v-if="generating" name="refresh" size="sm" class="mr-1 animate-spin" />
            <Icon v-else name="sparkles" size="sm" class="mr-1" />
            {{ t('admin.tlsFingerprintProfiles.form.generateAndCreate') }}
          </button>
        </div>
      </template>
    </BaseDialog>

    <!-- Delete Confirmation -->
    <ConfirmDialog
      :show="showDeleteDialog"
      :title="t('admin.tlsFingerprintProfiles.deleteProfile')"
      :message="t('admin.tlsFingerprintProfiles.deleteConfirmMessage', { name: deletingProfile?.name })"
      :confirm-text="t('common.delete')"
      :cancel-text="t('common.cancel')"
      :danger="true"
      @confirm="confirmDelete"
      @cancel="showDeleteDialog = false"
    />
  </BaseDialog>
</template>

<script setup lang="ts">
import { ref, reactive, watch } from 'vue'
import { useI18n } from 'vue-i18n'
import { useAppStore } from '@/stores/app'
import { adminAPI } from '@/api/admin'
import type { TLSFingerprintProfile } from '@/api/admin/tlsFingerprintProfile'
import BaseDialog from '@/components/common/BaseDialog.vue'
import ConfirmDialog from '@/components/common/ConfirmDialog.vue'
import Icon from '@/components/icons/Icon.vue'

const props = defineProps<{
  show: boolean
}>()

const emit = defineEmits<{
  close: []
}>()

// eslint-disable-next-line @typescript-eslint/no-unused-vars
void emit // suppress unused warning - emit is used via $emit in template

const { t } = useI18n()
const appStore = useAppStore()

const profiles = ref<TLSFingerprintProfile[]>([])
const loading = ref(false)
const submitting = ref(false)
const showCreateModal = ref(false)
const showEditModal = ref(false)
const showGenerateModal = ref(false)
const showDeleteDialog = ref(false)
const editingProfile = ref<TLSFingerprintProfile | null>(null)
const deletingProfile = ref<TLSFingerprintProfile | null>(null)
const yamlInput = ref('')
const generating = ref(false)
const generatedNotes = ref<string[]>([])

// Raw string inputs for array fields
const fieldInputs = reactive({
  cipher_suites: '',
  curves: '',
  point_formats: '',
  signature_algorithms: '',
  alpn_protocols: '',
  supported_versions: '',
  key_share_groups: '',
  psk_modes: '',
  extensions: ''
})

const form = reactive({
  name: '',
  description: null as string | null,
  enable_grease: false
})

const generatorForm = reactive({
  name: '',
  description: '',
  runtime: 'node',
  runtime_version: '',
  node_major: 24,
  openssl_version: '',
  transport: 'fetch',
  http_client: 'undici/fetch',
  websocket_client: 'ws',
  proxy_mode: 'none',
  mtls_enabled: false,
  custom_ca_enabled: false,
  alpn_protocols: '',
  enable_grease: 'auto'
})

// Load profiles when dialog opens
watch(() => props.show, (newVal) => {
  if (newVal) {
    loadProfiles()
  }
})

const loadProfiles = async () => {
  loading.value = true
  try {
    profiles.value = await adminAPI.tlsFingerprintProfiles.list()
  } catch (error) {
    appStore.showError(t('admin.tlsFingerprintProfiles.loadFailed'))
    console.error('Error loading TLS fingerprint profiles:', error)
  } finally {
    loading.value = false
  }
}

const resetForm = () => {
  form.name = ''
  form.description = null
  form.enable_grease = false
  fieldInputs.cipher_suites = ''
  fieldInputs.curves = ''
  fieldInputs.point_formats = ''
  fieldInputs.signature_algorithms = ''
  fieldInputs.alpn_protocols = ''
  fieldInputs.supported_versions = ''
  fieldInputs.key_share_groups = ''
  fieldInputs.psk_modes = ''
  fieldInputs.extensions = ''
  yamlInput.value = ''
}

const resetGeneratorForm = () => {
  generatedNotes.value = []
  generatorForm.name = ''
  generatorForm.description = ''
  generatorForm.runtime = 'node'
  generatorForm.runtime_version = ''
  generatorForm.node_major = 24
  generatorForm.openssl_version = ''
  generatorForm.transport = 'fetch'
  generatorForm.http_client = 'undici/fetch'
  generatorForm.websocket_client = 'ws'
  generatorForm.proxy_mode = 'none'
  generatorForm.mtls_enabled = false
  generatorForm.custom_ca_enabled = false
  generatorForm.alpn_protocols = ''
  generatorForm.enable_grease = 'auto'
}

/**
 * Parse YAML output from tls-fingerprint-web and fill form fields.
 * Expected format:
 *   # comment lines
 *   profile_key:
 *     name: "Profile Name"
 *     enable_grease: false
 *     cipher_suites: [4866, 4867, ...]
 *     alpn_protocols: ["h2", "http/1.1"]
 *     ...
 */
const parseYamlInput = () => {
  const text = yamlInput.value.trim()
  if (!text) return

  // Simple YAML parser for flat key-value structure
  // Extracts "key: value" lines, handling arrays like [1, 2, 3] and ["h2", "http/1.1"]
  const lines = text.split('\n')

  let foundName = false

  for (const line of lines) {
    const trimmed = line.trim()
    // Skip comments and empty lines
    if (!trimmed || trimmed.startsWith('#')) continue

    // Match "key: value" pattern (must have at least 2 leading spaces to be a property)
    const match = trimmed.match(/^(\w+):\s*(.+)$/)
    if (!match) continue

    const [, key, rawValue] = match
    const value = rawValue.trim()

    switch (key) {
      case 'name': {
        // Remove surrounding quotes
        const unquoted = value.replace(/^["']|["']$/g, '')
        if (unquoted) {
          form.name = unquoted
          foundName = true
        }
        break
      }
      case 'enable_grease':
        form.enable_grease = value === 'true'
        break
      case 'cipher_suites':
      case 'curves':
      case 'point_formats':
      case 'signature_algorithms':
      case 'supported_versions':
      case 'key_share_groups':
      case 'psk_modes':
      case 'extensions': {
        // Parse YAML array: [1, 2, 3] — values are decimal integers from tls-fingerprint-web
        const arrMatch = value.match(/^\[(.*)?\]$/)
        if (arrMatch) {
          const inner = arrMatch[1] || ''
          fieldInputs[key as keyof typeof fieldInputs] = inner
            .split(',')
            .map(s => s.trim())
            .filter(s => s.length > 0)
            .join(', ')
        }
        break
      }
      case 'alpn_protocols': {
        // Parse string array: ["h2", "http/1.1"]
        const arrMatch = value.match(/^\[(.*)?\]$/)
        if (arrMatch) {
          const inner = arrMatch[1] || ''
          fieldInputs.alpn_protocols = inner
            .split(',')
            .map(s => s.trim().replace(/^["']|["']$/g, ''))
            .filter(s => s.length > 0)
            .join(', ')
        }
        break
      }
    }
  }

  if (foundName) {
    appStore.showSuccess(t('admin.tlsFingerprintProfiles.form.yamlParsed'))
  } else {
    appStore.showError(t('admin.tlsFingerprintProfiles.form.yamlParseFailed'))
  }
}

// Auto-parse on paste event
const handleYamlPaste = () => {
  // Use nextTick to ensure v-model has updated
  setTimeout(() => parseYamlInput(), 50)
}

const closeFormModal = () => {
  showCreateModal.value = false
  showEditModal.value = false
  editingProfile.value = null
  resetForm()
}

const openCreateModal = () => {
  resetForm()
  showCreateModal.value = true
}

const openGenerateModal = () => {
  resetGeneratorForm()
  showGenerateModal.value = true
}

const closeGenerateModal = () => {
  showGenerateModal.value = false
  resetGeneratorForm()
}

// Parse a comma-separated string of numbers supporting both hex (0x...) and decimal
const parseNumericArray = (input: string): number[] => {
  if (!input.trim()) return []
  return input
    .split(',')
    .map(s => s.trim())
    .filter(s => s.length > 0)
    .map(s => s.startsWith('0x') || s.startsWith('0X') ? parseInt(s, 16) : parseInt(s, 10))
    .filter(n => !isNaN(n))
}

// Parse a comma-separated string of string values
const parseStringArray = (input: string): string[] => {
  if (!input.trim()) return []
  return input
    .split(',')
    .map(s => s.trim())
    .filter(s => s.length > 0)
}

const buildProfilePayload = (profile: TLSFingerprintProfile) => ({
  name: profile.name,
  description: profile.description ?? null,
  enable_grease: profile.enable_grease,
  cipher_suites: profile.cipher_suites ?? [],
  curves: profile.curves ?? [],
  point_formats: profile.point_formats ?? [],
  signature_algorithms: profile.signature_algorithms ?? [],
  alpn_protocols: profile.alpn_protocols ?? [],
  supported_versions: profile.supported_versions ?? [],
  key_share_groups: profile.key_share_groups ?? [],
  psk_modes: profile.psk_modes ?? [],
  extensions: profile.extensions ?? []
})

const applyProfileToForm = (profile: TLSFingerprintProfile) => {
  form.name = profile.name
  form.description = profile.description
  form.enable_grease = profile.enable_grease
  fieldInputs.cipher_suites = formatNumericArray(profile.cipher_suites)
  fieldInputs.curves = formatPlainNumericArray(profile.curves)
  fieldInputs.point_formats = formatPlainNumericArray(profile.point_formats)
  fieldInputs.signature_algorithms = formatNumericArray(profile.signature_algorithms)
  fieldInputs.alpn_protocols = (profile.alpn_protocols ?? []).join(', ')
  fieldInputs.supported_versions = formatNumericArray(profile.supported_versions)
  fieldInputs.key_share_groups = formatPlainNumericArray(profile.key_share_groups)
  fieldInputs.psk_modes = formatPlainNumericArray(profile.psk_modes)
  fieldInputs.extensions = formatNumericArray(profile.extensions)
}

const buildGenerateRequest = () => {
  const enableGREASE =
    generatorForm.enable_grease === 'auto' ? undefined : generatorForm.enable_grease === 'true'

  return {
    name: generatorForm.name.trim() || undefined,
    description: generatorForm.description.trim() || null,
    runtime: generatorForm.runtime,
    runtime_version: generatorForm.runtime_version.trim() || undefined,
    node_major: generatorForm.node_major || undefined,
    openssl_version: generatorForm.openssl_version.trim() || undefined,
    transport: generatorForm.transport,
    http_client: generatorForm.http_client.trim() || undefined,
    websocket_client: generatorForm.websocket_client.trim() || undefined,
    proxy_mode: generatorForm.proxy_mode,
    mtls_enabled: generatorForm.mtls_enabled,
    custom_ca_enabled: generatorForm.custom_ca_enabled,
    alpn_protocols: parseStringArray(generatorForm.alpn_protocols),
    enable_grease: enableGREASE
  }
}

const handleGenerateSubmit = async () => {
  if (!generatorForm.name.trim()) {
    appStore.showError(t('admin.tlsFingerprintProfiles.form.name') + ' ' + t('common.required'))
    return
  }

  generating.value = true
  try {
    const result = await adminAPI.tlsFingerprintProfiles.generate(buildGenerateRequest())
    generatedNotes.value = result.notes ?? []

    await adminAPI.tlsFingerprintProfiles.create(buildProfilePayload(result.profile))
    appStore.showSuccess(t('admin.tlsFingerprintProfiles.generateCreateSuccess'))
    closeGenerateModal()
    loadProfiles()
  } catch (error: any) {
    appStore.showError(error.response?.data?.detail || t('admin.tlsFingerprintProfiles.form.generateCreateFailed'))
    console.error('Error generating TLS fingerprint profile:', error)
  } finally {
    generating.value = false
  }
}

// Format a number as hex with 0x prefix and 4-digit padding
const formatHex = (n: number): string => '0x' + n.toString(16).padStart(4, '0')

// Format numeric arrays for display in textarea (null-safe)
const formatNumericArray = (arr: number[] | null | undefined): string => (arr ?? []).map(formatHex).join(', ')

// For point_formats and psk_modes (uint8), show as plain numbers (null-safe)
const formatPlainNumericArray = (arr: number[] | null | undefined): string => (arr ?? []).join(', ')

const handleEdit = (profile: TLSFingerprintProfile) => {
  editingProfile.value = profile
  generatedNotes.value = []
  applyProfileToForm(profile)
  showEditModal.value = true
}

const handleDelete = (profile: TLSFingerprintProfile) => {
  deletingProfile.value = profile
  showDeleteDialog.value = true
}

const handleSubmit = async () => {
  if (!form.name.trim()) {
    appStore.showError(t('admin.tlsFingerprintProfiles.form.name') + ' ' + t('common.required'))
    return
  }

  submitting.value = true
  try {
    const data = {
      name: form.name.trim(),
      description: form.description?.trim() || null,
      enable_grease: form.enable_grease,
      cipher_suites: parseNumericArray(fieldInputs.cipher_suites),
      curves: parseNumericArray(fieldInputs.curves),
      point_formats: parseNumericArray(fieldInputs.point_formats),
      signature_algorithms: parseNumericArray(fieldInputs.signature_algorithms),
      alpn_protocols: parseStringArray(fieldInputs.alpn_protocols),
      supported_versions: parseNumericArray(fieldInputs.supported_versions),
      key_share_groups: parseNumericArray(fieldInputs.key_share_groups),
      psk_modes: parseNumericArray(fieldInputs.psk_modes),
      extensions: parseNumericArray(fieldInputs.extensions)
    }

    if (showEditModal.value && editingProfile.value) {
      await adminAPI.tlsFingerprintProfiles.update(editingProfile.value.id, data)
      appStore.showSuccess(t('admin.tlsFingerprintProfiles.updateSuccess'))
    } else {
      await adminAPI.tlsFingerprintProfiles.create(data)
      appStore.showSuccess(t('admin.tlsFingerprintProfiles.createSuccess'))
    }

    closeFormModal()
    loadProfiles()
  } catch (error: any) {
    appStore.showError(error.response?.data?.detail || t('admin.tlsFingerprintProfiles.saveFailed'))
    console.error('Error saving TLS fingerprint profile:', error)
  } finally {
    submitting.value = false
  }
}

const confirmDelete = async () => {
  if (!deletingProfile.value) return

  try {
    await adminAPI.tlsFingerprintProfiles.delete(deletingProfile.value.id)
    appStore.showSuccess(t('admin.tlsFingerprintProfiles.deleteSuccess'))
    showDeleteDialog.value = false
    deletingProfile.value = null
    loadProfiles()
  } catch (error: any) {
    appStore.showError(error.response?.data?.detail || t('admin.tlsFingerprintProfiles.deleteFailed'))
    console.error('Error deleting TLS fingerprint profile:', error)
  }
}
</script>
