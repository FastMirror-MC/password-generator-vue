<script setup lang="ts">
import { computed, ref, useModel } from 'vue';

const props = defineProps<{
    min: number,
    max: number,
    modelValue: number
}>()

const sliderRef = ref()

const value = useModel(props, 'modelValue')

const currentPrecent = computed(() => {
    return `${((value.value - props.min) / (props.max - props.min)) * 100}%`
})

let isListening = ref(false);

const setValue = (event: PointerEvent) => {
    const { clientX } = event
    const { left, width } = sliderRef.value.getBoundingClientRect()
    const precent = (clientX - left) / width

    let result = Math.round(precent * (props.max - props.min) + props.min)
    if (result < props.min) result = props.min
    if (result > props.max) result = props.max
    value.value = result
}

const onTouchMove = (event: Event) => {
    if (event.cancelable) {
        event.preventDefault()
    }
}

const onPointerDown = (event: PointerEvent) => {
    event.preventDefault()
    if (isListening.value) return;
    isListening.value = true
    window.addEventListener('touchmove', onTouchMove, { passive: false })
    window.addEventListener('pointermove', onPointerMove)
    window.addEventListener('pointerup', onPointerUp)
    setValue(event)
}

const onPointerMove = (event: PointerEvent) => {
    event.preventDefault()
    setValue(event)
}

const onPointerUp = (event: PointerEvent) => {
    event.preventDefault()
    isListening.value = false
    window.removeEventListener('touchmove', onTouchMove)
    window.removeEventListener('pointermove', onPointerMove)
    window.removeEventListener('pointerup', onPointerUp)
    setValue(event)
}
</script>

<template>
    <div class="range-input-wrapper">
        <div class="slider-wrapper">
            <div ref="sliderRef" class="slider" :style="{
                '--precent': currentPrecent
            }" :class="{ active: isListening }" @pointerdown="onPointerDown">
                <div class="slider__bar"></div>
                <div class="slider__button"></div>
                <div class="slider__protip">{{ value }}</div>
            </div>
        </div>
        <input type="number" v-model="value" :min="min" :max="max" />
    </div>
</template>

<style scoped lang="scss">
.range-input-wrapper {
    @apply w-full relative select-none;
    @apply flex items-center gap-2;
}

.slider-wrapper {
    @apply px-2 flex-grow;
}

input {
    @apply border border-2 border-primary/30 text-sm h-6 w-12;
    @apply rounded-2xl text-primary text-center outline-none;
    -moz-appearance: textfield;
    &::-webkit-outer-spin-button,
    &::-webkit-inner-spin-button {
        -webkit-appearance: none;
        appearance: none;
        margin: 0;
    }
}

.slider {
    @apply w-full h-2;
    @apply relative;
    @apply cursor-pointer;

    * {
        @apply pointer-events-none;
    }

    &::before {
        @apply block absolute h-full absolute top-0 left-0 -right-2;
        @apply rounded-2xl content-[''] bg-primary/30;
    }

    .slider__bar {
        @apply h-2 w-[var(--precent)] bg-primary;
        @apply rounded-2xl;
        @apply absolute top-1/2;
        @apply transform-gpu -translate-y-1/2;
        @apply transition;
        transition-property: height;
    }

    .slider__button {
        @apply pointer-events-auto;
        @apply w-5 h-5 bg-white;
        @apply absolute top-1/2 left-[var(--precent)];
        @apply transform-gpu -translate-y-1/2 -translate-x-1/2;
        @apply rounded-full transition;
        @apply border-2 border-primary;
        @apply cursor-grab;

        &:hover {
            @apply bg-primary-light;
        }

        &:active {
            @apply cursor-grabbing;
        }
    }

    .slider__protip {
        @apply hidden;
        @apply absolute -top-3 left-[var(--precent)];
        @apply transform-gpu -translate-x-1/2 -translate-y-15px scale-80;
        @apply text-primary px-2;
        @apply rounded-lg border-2 border border-primary/0;
        @apply transition duration-300 opacity-0;
    }

    &:hover,
    &.active {
        .slider__bar {
            @apply h-4;
        }

        .slider__protip {
            @apply -translate-y-full opacity-100;
            @apply border-primary/50 border-2 bg-white/80 scale-100;
        }
    }
}
</style>