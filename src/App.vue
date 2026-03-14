<script setup lang="ts">
import { reactive, ref, watch, computed } from 'vue';
import PasswordBox from './components/PasswordBox.vue';
import RangeInput from './components/RangeInput.vue';
import SwitchInput from './components/SwitchInput.vue';
import { useDebounceFn } from '@vueuse/core'
import { generatePassword, checkSecurity } from './utils';

const password = ref('');
const passwordLength = ref(16);
const config = reactive({
  includeNumber: true,
  includeLowercase: true,
  includeUppercase: true,
  includeSymbol: false,
  ignoreChars: false
})
const ignoreChars = ref('oO0lI1');

export interface SecurityItem {
  type: 'warn' | 'error';
  text: string;
  desc: string;
}

const security = reactive([] as SecurityItem[]);

const debouncedCheckSecurity = useDebounceFn((password: string) => {
  security.length = 0;
  security.push(...checkSecurity(password))
}, 100)

const refreshPassword = () => {
  const result = generatePassword({
    length: passwordLength.value,
    numbers: config.includeNumber,
    lowercase: config.includeLowercase,
    uppercase: config.includeUppercase,
    special: config.includeSymbol,
    ignore: config.ignoreChars ? ignoreChars.value : ''
  });
  password.value = result;
}

watch([passwordLength, config, ignoreChars], refreshPassword, { immediate: true });

watch(password, (val: string) => {
  if (password.value.includes(' ')) {
    password.value = password.value.replace(/\s/g, '');
    return;
  }
  if (password.value.length < 0) {
    security.length = 0;
    return;
  }
  debouncedCheckSecurity(val);
});

const minPasswordLength = computed(() => {
  let count = 0;
  if (config.includeNumber) count++;
  if (config.includeLowercase) count++;
  if (config.includeUppercase) count++;
  if (config.includeSymbol) count++;
  return count > 0 ? count : 1; // Ensure at least 1
});

</script>

<template>
  <main>
    <PasswordBox v-model="password" />
    <div class="input-wrapper">
      <span class="label">
        密码长度：
      </span>
      <RangeInput v-model="passwordLength" :min="minPasswordLength" :max="100" />
    </div>
    <div class="input-wrapper">
      <span class="label">
        包含数字：
      </span>
      <SwitchInput v-model="config.includeNumber" />
    </div>
    <div class="input-wrapper">
      <span class="label">
        包含小写字母：
      </span>
      <SwitchInput v-model="config.includeLowercase" />
    </div>
    <div class="input-wrapper">
      <span class="label">
        包含大写字母：
      </span>
      <SwitchInput v-model="config.includeUppercase" />
    </div>
    <div class="input-wrapper">
      <span class="label">
        包含特殊符号：
      </span>
      <SwitchInput v-model="config.includeSymbol" />
    </div>
    <div class="flex flex-col gap-2">
      <div class="input-wrapper">
        <span class="label">
          排除字符：
        </span>
        <SwitchInput v-model="config.ignoreChars" />
      </div>
      <input class="ignore-input" :class="{ hide: !config.ignoreChars }" type="text" v-model="ignoreChars" />
    </div>
    <button class="block-btn" @click="refreshPassword">生成密码</button>
    <div v-if="security.length !== 0" class="security-wrapper">
      <div class="security-item" :class="[item.type]" v-for="item in security" :key="item.text">
        <div v-if="item.type == 'warn'" class="icon i-mingcute:alert-fill"></div>
        <div v-if="item.type == 'error'" class="icon i-mingcute:alert-octagon-fill"></div>
        <div>
          <p class="security-text">
            {{ item.text }}
          </p>
          <p class="security-desc">
            {{ item.desc }}
          </p>
        </div>
      </div>
    </div>
  </main>
  <footer>
    <a href="https://beian.miit.gov.cn/" target="_blank" rel="noopener noreferrer">
      京ICP备2021028678号-4
    </a>
  </footer>
</template>

<style scoped lang="scss">
main {
  @apply "static sm:(fixed top-1/2 left-1/2 transform -translate-x-1/2 -translate-y-1/2)";
  @apply max-w-90vw w-400px;
  @apply bg-white;
  @apply p-3;
  @apply rounded-3xl;
  @apply flex flex-col gap-4 relative;
  @apply <sm: mt-15;
  margin: 0 auto;

  &::after {
    @apply block absolute -top-5 left-0 right-0 text-center;
    @apply content-['密码生成器'] transform-gpu -translate-y-full;
    @apply pointer-events-none font-bold text-primary text-4xl;
  }
}

.input-wrapper {
  @apply flex items-center justify-between;
}

.label {
  @apply flex-shrink-0 text-primary font-bold text-lg select-none;
}

.ignore-input {
  @apply border border-2 border-primary/30;
  @apply rounded-2xl;
  @apply px-2 py-1 text-lg outline-none text-primary;
  @apply font-serif;
  @apply transition-all;
  @apply opacity-100;

  &.hide {
    @apply pointer-events-none -mt-13 opacity-0;
  }
}

.block-btn {
  @apply bg-primary text-white text-xl font-light;
  @apply py-3 rounded-xl transition select-none;

  &:hover {
    @apply bg-primary/80;
  }

  &:active {
    @apply bg-primary/90;
  }
}

.security-wrapper {
  @apply flex flex-col gap-2 select-none;

  .security-item {
    @apply px-3 py-2 flex gap-2 rounded-xl;

    &.warn {
      @apply text-amber-6 bg-amber-1;
    }

    &.error {
      @apply text-red-6 bg-red-1;
    }

    .icon {
      @apply flex-shrink-0 text-2xl;
    }

    .security-text {
      @apply font-bold;
    }

    .security-desc {
      @apply text-sm opacity-70;
    }
  }
}

footer {
  position: fixed;
  bottom: 0;
  left: 0;
  right: 0;
  @apply text-primary;
  @apply text-center;
}
</style>
