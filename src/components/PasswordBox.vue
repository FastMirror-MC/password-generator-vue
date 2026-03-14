<script setup lang="ts">
import { useModel } from 'vue';
import contenteditable from 'vue-contenteditable'

const props = defineProps<{
    modelValue: string
}>()

const password = useModel(props, 'modelValue')

const copy = () => {
    navigator.clipboard.writeText(password.value)
}
</script>

<template>
    <div class="password-box-wrapper">
        <contenteditable tag="span" class="outline-none" v-model="password" :no-html="true" :no-nl="true" :class="{
            'w-full': password.trim().length === 0
        }" />
        <div class="action-area">
            <button class="btn copy-btn" @click="copy">
                <div class="i-mingcute:copy-fill"></div>
            </button>
        </div>
    </div>
</template>

<style scoped lang="scss">
.password-box-wrapper {
    @apply w-full;
    @apply rounded-2xl;
    @apply relative;
    @apply flex justify-center;
    @apply bg-primary/30;

    &:hover {
        .action-area {
            @apply opacity-100;
        }
    }
}

span {
    @apply bg-transparent text-primary max-w-full;
    @apply px-3 py-4 text-lg;
    @apply inline-block;
    @apply whitespace-pre-wrap break-all;
}

.action-area {
    @apply absolute top-2 right-2 flex items-center;
    @apply opacity-0 transition-opacity;
}

.btn {
    @apply w-7 h-7 text-primary bg-white select-none;
    @apply rounded-lg;
    @apply flex items-center justify-center;
    @apply transition duration-300 cursor-pointer;

    div {
        @apply w-4 h-4 text-current;
        @apply mx-auto;
        @apply pointer-events-none;
    }

    &:hover {
        @apply ring-1 ring-primary;
    }

    &:active {
        @apply bg-primary/80 text-white;
    }
}
</style>