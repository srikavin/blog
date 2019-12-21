import React from 'react';
import ReactDOM from 'react-dom';
import './index.module.css';
import App from './App';
import {BrowserRouter, withRouter} from 'react-router-dom'
import {unregister} from './registerServiceWorker';
import ReactGA from 'react-ga';
import config from './config'

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

ReactDOM.render((
    <BrowserRouter>
        <GAListener>
            <ScrollToTopWrapped>
                <App/>
            </ScrollToTopWrapped>
        </GAListener>
    </BrowserRouter>
), document.getElementById('root'));

unregister();
