<script setup lang="ts">
import { useModel } from 'vue';

const props = defineProps<{
    modelValue: boolean
}>()

const state = useModel(props, 'modelValue')

</script>

<template>
    <div class="switch-wrapper" :class="{
        active: state,
    }" @click.prevent="state = !state">
        <div class="switch__track">
            <div class="switch__inner">
                <div class="switch__trumb"></div>
            </div>
        </div>
    </div>
</template>

<style scoped lang="scss">
.switch-wrapper {
    @apply h-6 w-12 cursor-pointer;

    .switch__track {
        @apply h-full rounded-full;
        @apply border border-2 border-primary/30;
    }

    .switch__inner {
        @apply mx-0.5 relative h-full;
    }

    .switch__inner::before {
        @apply absolute bg-primary/30;
        @apply top-0.5 left-0 right-6 bottom-0.5 rounded-full;
        @apply content-[''];
        @apply transition;
        transition-property: right;
    }

    .switch__trumb {
        @apply h-4 w-4 rounded-full;
        @apply bg-primary;
        @apply transition-transform duration-200;
        @apply absolute top-1/2 left-0;
        @apply transform-gpu -translate-y-1/2;
    }

    &:hover {
        .switch__trumb {
            @apply scale-140;
        }
    }

    &.active {
        .switch__trumb {
            @apply translate-x-6;
        }

        .switch__inner::before {
            @apply right-0;
        }
    }
}
</style>