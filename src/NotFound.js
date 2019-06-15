import React, {Component} from 'react';
import ErrorState from './components/util/ErrorState/ErrorState';
import {FaExclamationTriangle} from 'react-icons/fa';
import {Link} from 'react-router-dom';

class NotFound extends Component {
    render() {
        if (this.props.history.location.pathname !== '/404') {
            window.location.pathname = '/404';
        }
        return (
            <ErrorState title={'404 Page not Found'}
                        description={'The requested page could not be found'}
                        icon={<FaExclamationTriangle/>}
                        action={<Link to={'/'}>Go home</Link>}/>
        );
    }
}

NotFound.propTypes = {};

export default NotFound;