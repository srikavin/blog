import React from 'react';
import {hydrate, render} from "react-dom";
import './index.css';
import App from './App';
import {BrowserRouter, withRouter} from 'react-router-dom'
import {unregister} from './registerServiceWorker';
import ReactGA from 'react-ga';

import config from './config'
import ThemeSelector from "./components/ThemeSelector/ThemeSelector";

ReactGA.initialize(config['google-analytics-key'], {
    standardImplementation: true
});

let ScrollToTopWrapped = withRouter(class ScrollToTop extends React.Component {
    componentDidUpdate(prevProps) {
        if (this.props.location !== prevProps.location) {
            window.scrollTo(0, 0)
        }
    }

    render() {
        return this.props.children
    }
});

class _GAListener extends React.Component {
    static sendPageView(location) {
        ReactGA.set({page: location.pathname});
        ReactGA.pageview(location.pathname);
    }

    componentDidUpdate() {
        _GAListener.sendPageView(this.props.location);
    }

    render() {
        return this.props.children;
    }
}

const GAListener = withRouter(_GAListener);

const root = (
    <BrowserRouter>
        <GAListener>
            <ScrollToTopWrapped>
                <ThemeSelector>
                    <App/>
                </ThemeSelector>
            </ScrollToTopWrapped>
        </GAListener>
    </BrowserRouter>
)

const rootElement = document.getElementById("root");

if (rootElement.hasChildNodes()) {
    hydrate(root, rootElement);
} else {
    render(root, rootElement);
}

unregister();
