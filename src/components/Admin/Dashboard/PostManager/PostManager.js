import React, {Component} from 'react';
import {NavLink, Redirect, Route, Switch} from 'react-router-dom';
import DraftList from './DraftList/DraftList';
import PublishedList from './PublishedList/PublishedList';
import {Button, ButtonGroup} from '@blueprintjs/core';
import styles from '../Dashboard.module.css';
import PropTypes from 'prop-types';

class PostManager extends Component {
    render() {
        return (
            <>
                <div className={this.props.containerClassName}>
                    <ButtonGroup minimal={true}>
                        <NavLink activeClassName={styles.active} to={`${this.props.match.url}/published`}>
                            <Button>Published</Button>
                        </NavLink>
                        <NavLink activeClassName={styles.active} to={`${this.props.match.url}/drafts`}>
                            <Button>Drafts</Button>
                        </NavLink>
                    </ButtonGroup>
                </div>
                <Switch>
                    <Route path={`${this.props.match.url}/published`} component={PublishedList}/>
                    <Route path={`${this.props.match.url}/drafts`} component={DraftList}/>
                    <Route render={() => <Redirect to={`${this.props.match.url}/published`}/>}/>
                </Switch>
            </>
        );
    }
}

PostManager.propTypes = {
    containerClassName: PropTypes.string
};

export default PostManager;