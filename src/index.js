import React from 'react';
import ReactDOM from 'react-dom';
import './index.module.css';
import App from './App';
import {BrowserRouter, withRouter} from 'react-router-dom'
import registerServiceWorker from './registerServiceWorker';

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

ReactDOM.render((
    <BrowserRouter>
        <ScrollToTopWrapped>
            <App/>
        </ScrollToTopWrapped>
    </BrowserRouter>
), document.getElementById('root'));
registerServiceWorker();
