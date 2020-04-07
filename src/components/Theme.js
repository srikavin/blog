import {createContext} from 'react';

export type Theme = 'light' | 'dark'

export const LIGHT_THEME: Theme = 'light'
export const DARK_THEME: Theme = 'dark'

export const ThemeContext = createContext(LIGHT_THEME)
ThemeContext.data = 'dark'
ThemeContext.displayName = 'Theme'