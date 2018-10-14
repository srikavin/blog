import React from 'react';
import ReactDOM from 'react-dom';
import './index.module.css';
import App from './App';
import PropTypes from 'prop-types';
import {BrowserRouter, withRouter} from 'react-router-dom'
import {unregister} from './registerServiceWorker';
import ReactGA from 'react-ga';

ReactGA.initialize('UA-125481234-1');

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

class GAListener extends React.Component {
    static contextTypes = {
        router: PropTypes.object
    };

    componentDidMount() {
        this.sendPageView(this.context.router.history.location);
        this.context.router.history.listen(this.sendPageView);
    }

    sendPageView(location) {
        ReactGA.set({page: location.pathname});
        ReactGA.pageview(location.pathname);
    }

    render() {
        return this.props.children;
    }
}

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
